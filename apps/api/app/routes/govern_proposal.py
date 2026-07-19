"""
Governance proposal route: single fail-closed choke point.

Wire order (fail-closed at each stage):
1. SessionRiskTracker (cumulative topology detection)
2. Tripwire scan on any code artifacts (Phase 4+5)
3. Require challenge-response if decision is REQUIRE_HUMAN
4. Commit effects only on ALLOW or human approval

All enforcement happens in the Runner—the only component authorized to
execute tools—so policy can't be bypassed by upstream orchestration.

This module also exports helper functions that /v1 endpoints can use
to delegate into the Phase 3-6 enforcement lane (no bypass).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

import redis

from ..session_risk import SessionRiskTracker
from ..governance.resource_limits import (
    bounded_python_tripwire_scan,
    GovernanceTimeout,
    GovernanceLimitExceeded,
)
from ..governance.adversarial_review import (
    stable_proposal_hash,
    generate_challenge,
    verify_challenge,
    require_secure_challenge_config,
    save_challenge,
    consume_challenge,
    Challenge,
)

router = APIRouter(prefix="/v2/govern", tags=["governance"])


# ---- Request/Response Models ----

class Artifact(BaseModel):
    type: str
    content: Optional[str] = None
    path: Optional[str] = None


class ProposalRequest(BaseModel):
    principal_id: str
    agent_name: str
    effects: List[str]
    artifacts: List[Artifact] = []
    proposal_id: Optional[str] = None
    summary: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ChallengeResponse(BaseModel):
    challenge_id: str
    proposal_hash: str
    prompt: str


class GovernanceResponse(BaseModel):
    decision: str  # ALLOW | REQUIRE_HUMAN | DENY
    reason: str
    challenge: Optional[ChallengeResponse] = None
    proposal_hash: Optional[str] = None


class ApprovalRequest(BaseModel):
    principal_id: str
    agent_name: str
    effects: List[str]
    proposal: Dict[str, Any]
    challenge_id: str
    answer: str


# ---- Fail-closed authentication for override endpoints ----

def require_governance_auth(authorization: str = Header(default="")) -> None:
    """Fail-closed bearer check on the governance override surface.

    The proposal and approve endpoints mutate session-risk state and clear
    human-override gates; they must not be anonymous. The expected token is
    read from M87_GOVERNANCE_API_TOKEN. If that is unset the endpoint refuses
    all calls (503) rather than defaulting open — no token, no access.
    """
    import os
    expected = os.environ.get("M87_GOVERNANCE_API_TOKEN", "")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Governance auth not configured (M87_GOVERNANCE_API_TOKEN unset).",
        )
    prefix = "Bearer "
    presented = authorization[len(prefix):] if authorization.startswith(prefix) else ""
    import hmac as _hmac
    if not presented or not _hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token.")


# ---- Dependencies ----

def get_redis() -> redis.Redis:
    """
    Get Redis connection.

    Replace with your existing dependency injection.
    """
    import os
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(redis_url, decode_responses=False)


# ---- Pure Helper Functions (for /v1 delegation) ----
# These can be called from legacy endpoints to enforce Phase 3-6 governance.

def evaluate_governance_proposal(payload: Dict[str, Any], r: redis.Redis) -> Dict[str, Any]:
    """
    Core governance evaluation logic.

    Can be called from /v1 or /v2 endpoints.
    Returns dict with: decision, reason, challenge (if REQUIRE_HUMAN), proposal_hash
    """
    principal_id = payload.get("principal_id") or "unknown"
    agent_name = payload.get("agent_name") or payload.get("agent") or "unknown"
    proposed_effects = payload.get("effects") or []
    artifacts = payload.get("artifacts") or []

    tracker = SessionRiskTracker(r=r)

    # Phase 3: Evaluate against session history (toxic topologies)
    decision, reason = tracker.evaluate(principal_id, agent_name, proposed_effects)

    # Phase 4/5: Inspect code artifacts BEFORE allowing execution paths
    tripwire_flags: List[str] = []
    for artifact in artifacts:
        artifact_type = artifact.get("type") if isinstance(artifact, dict) else getattr(artifact, "type", None)
        artifact_content = artifact.get("content") if isinstance(artifact, dict) else getattr(artifact, "content", None)

        if artifact_type in ("python_code", "code", "shell_script"):
            code = artifact_content or ""
            try:
                scan = bounded_python_tripwire_scan(code)
            except GovernanceTimeout:
                raise HTTPException(
                    status_code=403,
                    detail="Governance scan blocked: timeout"
                )
            except GovernanceLimitExceeded as e:
                raise HTTPException(
                    status_code=403,
                    detail=f"Governance scan blocked: {str(e)}"
                )

            if not scan.get("ok", False):
                tripwire_flags.extend(scan.get("flags", []))

    # If tripwire flags found, escalate to REQUIRE_HUMAN
    if tripwire_flags and decision == "ALLOW":
        decision = "REQUIRE_HUMAN"
        reason = f"{reason} | Tripwire flags: {tripwire_flags}"

    # Compute stable proposal hash for challenge binding
    proposal_json = payload.get("_proposal_json")
    if not isinstance(proposal_json, str):
        proposal_json = json.dumps(payload, sort_keys=True, default=str)
    p_hash = stable_proposal_hash(proposal_json)

    # Phase 6: Challenge-response for REQUIRE_HUMAN
    if decision == "REQUIRE_HUMAN":
        # Refuse to issue an override challenge under an insecure HMAC secret.
        require_secure_challenge_config()

        topology_name = "unknown_topology"
        if "Toxic topology detected:" in reason:
            try:
                topology_name = reason.split("Toxic topology detected:")[1].strip().split()[0]
            except Exception:
                pass

        challenge = generate_challenge(p_hash, topology_name)
        # Persist the expected answer server-side (single-use, TTL). The client
        # never receives it — that closes the bot-defeat where an automated
        # caller echoed the topology name back out of the response body.
        save_challenge(r, challenge)

        # Redact the specific topology name from the CLIENT-facing reason so the
        # response no longer discloses the challenge answer. The "Toxic topology"
        # marker is preserved; the exact name is shown only in the operator UI /
        # server logs, which is where a human obtains it to answer the challenge.
        client_reason = reason.replace(
            f"Toxic topology detected: {topology_name}",
            "Toxic topology detected (name shown in the operator console)",
        )

        return {
            "decision": decision,
            "reason": client_reason,
            "proposal_hash": p_hash,
            "challenge": {
                "challenge_id": challenge.challenge_id,
                "proposal_hash": challenge.proposal_hash,
                "prompt": challenge.prompt,
            },
        }

    if decision == "DENY":
        return {"decision": decision, "reason": reason, "proposal_hash": p_hash}

    # ALLOW: commit effects only now
    try:
        tracker.commit(principal_id, agent_name, proposed_effects)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Failed to persist governance state (Redis)."
        )

    return {"decision": "ALLOW", "reason": reason, "proposal_hash": p_hash}


def approve_governance_override(payload: Dict[str, Any], r: redis.Redis) -> Dict[str, Any]:
    """
    Core human override approval logic.

    Can be called from /v1 or /v2 endpoints.
    Verifies challenge-response and commits effects on success.
    """
    require_secure_challenge_config()

    principal_id = payload.get("principal_id") or "unknown"
    agent_name = payload.get("agent_name") or payload.get("agent") or "unknown"
    effects = payload.get("effects") or []
    answer = payload.get("answer") or ""
    challenge_id = payload.get("challenge_id") or ""

    # Load the pending challenge from server-side store (single-use). The
    # expected answer and proposal-hash binding come from here, NOT from the
    # client-supplied proposal — so a caller cannot derive or replay the answer.
    # Unknown / consumed / expired challenge all fail closed.
    stored = consume_challenge(r, challenge_id)
    if not stored:
        raise HTTPException(
            status_code=403,
            detail="Approval blocked: challenge unknown, already used, or expired",
        )

    ch = Challenge(
        challenge_id=challenge_id,
        prompt="",
        expected=stored.get("expected", ""),
        proposal_hash=stored.get("proposal_hash", ""),
    )
    p_hash = ch.proposal_hash

    # Verify the challenge (answer match + HMAC binding to the original proposal)
    result = verify_challenge(ch, answer)
    if result.get("ok") != "true":
        raise HTTPException(
            status_code=403,
            detail=f"Approval blocked: {result.get('reason')}"
        )

    # Commit effects after successful verification
    tracker = SessionRiskTracker(r=r)
    try:
        tracker.commit(principal_id, agent_name, effects)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Failed to persist governance state (Redis)."
        )

    return {"decision": "ALLOW", "reason": "Human override approved with challenge-response", "proposal_hash": p_hash}


# ---- Routes (v2) ----

@router.post("/proposal", response_model=GovernanceResponse)
def govern_proposal(
    payload: ProposalRequest,
    r: redis.Redis = Depends(get_redis),
    _auth: None = Depends(require_governance_auth),
) -> GovernanceResponse:
    """
    Main governance choke point (v2).

    Evaluates proposal against:
    1. Session risk (cumulative toxic topology detection)
    2. Code artifact tripwire scan
    3. Returns challenge if REQUIRE_HUMAN
    """
    # Convert Pydantic model to dict for helper
    payload_dict = payload.model_dump()
    payload_dict["_proposal_json"] = payload.model_dump_json()

    result = evaluate_governance_proposal(payload_dict, r)

    # Convert result to response model
    challenge = None
    if result.get("challenge"):
        challenge = ChallengeResponse(**result["challenge"])

    return GovernanceResponse(
        decision=result["decision"],
        reason=result["reason"],
        proposal_hash=result.get("proposal_hash"),
        challenge=challenge,
    )


@router.post("/approve", response_model=GovernanceResponse)
def approve_override(
    payload: ApprovalRequest,
    r: redis.Redis = Depends(get_redis),
    _auth: None = Depends(require_governance_auth),
) -> GovernanceResponse:
    """
    Human override approval with challenge-response verification (v2).

    Requires:
    1. Valid challenge response (proves human read the warning)
    2. Challenge binding to original proposal (prevents bait-switch)
    """
    # Convert Pydantic model to dict for helper
    payload_dict = payload.model_dump()
    payload_dict["_proposal_json"] = json.dumps(payload.proposal, sort_keys=True, default=str)

    result = approve_governance_override(payload_dict, r)

    return GovernanceResponse(
        decision=result["decision"],
        reason=result["reason"],
        proposal_hash=result.get("proposal_hash"),
    )
