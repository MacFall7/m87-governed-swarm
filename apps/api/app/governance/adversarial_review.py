"""
Phase 6 Oversight model: bind challenge-response to proposal hash.

Prevents replay attacks and bait-switch on human overrides.
The challenge is cryptographically bound to the proposal content.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Challenge:
    """
    A challenge for human override verification.

    challenge_id: HMAC signature binding proposal + expected answer
    prompt: Question to show the human
    expected: Expected answer (not returned to client in production)
    proposal_hash: Hash of the proposal being overridden
    """
    challenge_id: str
    prompt: str
    expected: str
    proposal_hash: str


def stable_proposal_hash(proposal_json: str) -> str:
    """
    Compute a stable hash of the proposal.

    The hash should be computed from canonical JSON to ensure stability.
    """
    return hashlib.sha256(
        proposal_json.encode("utf-8", errors="ignore")
    ).hexdigest()


def _get_challenge_secret() -> bytes:
    """Get the challenge signing secret from environment."""
    secret = os.environ.get("M87_CHALLENGE_SECRET", "dev-secret-change-me")
    return secret.encode("utf-8")


def _sign(value: str) -> str:
    """Sign a value with the challenge secret."""
    secret = _get_challenge_secret()
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


class InsecureChallengeConfig(RuntimeError):
    """Raised when the challenge secret is missing/default outside dev."""


def require_secure_challenge_config() -> None:
    """Fail closed at the request boundary if the HMAC secret is insecure.

    The pure challenge functions keep a permissive default so unit tests can
    exercise them without env setup. The deployed governance route calls this
    first, so a production Gate refuses to issue or verify overrides while the
    challenge secret is unset or left at the shipped placeholder — unless an
    operator explicitly opts into insecure mode for local dev.
    """
    secret = os.environ.get("M87_CHALLENGE_SECRET", "")
    if secret and secret != "dev-secret-change-me":
        return
    if os.environ.get("M87_ALLOW_INSECURE_CHALLENGE") == "1":
        return
    raise InsecureChallengeConfig(
        "M87_CHALLENGE_SECRET is unset or the shipped default. Set a real "
        "secret, or M87_ALLOW_INSECURE_CHALLENGE=1 for local dev only."
    )


# --- Server-side single-use challenge store --------------------------------
# The expected answer must NOT be derivable by the API client. It is persisted
# server-side, bound to the proposal hash, given a short TTL, and consumed on
# first successful verification so a leaked/observed answer cannot be replayed.

_CHALLENGE_TTL_SECONDS = 600


def _challenge_key(challenge_id: str) -> str:
    return f"m87:challenge:{challenge_id}"


def save_challenge(r, ch: "Challenge") -> None:
    """Persist a pending challenge (expected answer held server-side only)."""
    import json as _json
    r.setex(
        _challenge_key(ch.challenge_id),
        _CHALLENGE_TTL_SECONDS,
        _json.dumps({"expected": ch.expected, "proposal_hash": ch.proposal_hash}),
    )


def consume_challenge(r, challenge_id: str):
    """Atomically fetch-and-delete a pending challenge (single use).

    Returns the stored {expected, proposal_hash} dict, or None if the challenge
    is unknown, already consumed, or expired — all of which fail closed.
    """
    import json as _json
    key = _challenge_key(challenge_id)
    pipe = r.pipeline()
    pipe.get(key)
    pipe.delete(key)
    stored, _ = pipe.execute()
    if not stored:
        return None
    if isinstance(stored, bytes):
        stored = stored.decode("utf-8", errors="ignore")
    try:
        return _json.loads(stored)
    except Exception:
        return None


def generate_challenge(
    proposal_hash: str,
    topology_name: str = "repo_read_then_network"
) -> Challenge:
    """
    Generate a challenge for human override.

    The challenge requires the human to demonstrate they understand
    what they're approving by typing the exact topology name.

    Args:
        proposal_hash: Hash of the proposal being challenged
        topology_name: The toxic topology being overridden (set by UI/API)

    Returns:
        Challenge object with bound ID
    """
    prompt = (
        "Type the EXACT toxic topology name you are trying to override "
        "(as shown in the UI)."
    )
    expected = topology_name

    # Challenge ID is HMAC of proposal_hash + expected
    # This binds the challenge to both the proposal and the expected answer
    challenge_id = _sign(f"{proposal_hash}:{expected}")

    return Challenge(
        challenge_id=challenge_id,
        prompt=prompt,
        expected=expected,
        proposal_hash=proposal_hash
    )


def verify_challenge(ch: Challenge, user_answer: str) -> Dict[str, str]:
    """
    Verify a challenge response.

    Checks:
    1. User answer matches expected
    2. Challenge ID is valid (prevents tampering)

    Returns:
        {"ok": "true"/"false", "reason": str}
    """
    answer = (user_answer or "").strip()

    # Check answer matches
    if answer != ch.expected:
        return {"ok": "false", "reason": "challenge_failed"}

    # Verify challenge binding (prevents replay with different proposal)
    expected_id = _sign(f"{ch.proposal_hash}:{ch.expected}")
    if expected_id != ch.challenge_id:
        return {"ok": "false", "reason": "challenge_binding_failed"}

    return {"ok": "true", "reason": "challenge_passed"}


def generate_secondary_challenge(
    proposal_hash: str,
    effect_name: str
) -> Challenge:
    """
    Generate a secondary challenge for high-risk effects.

    Used when overriding particularly dangerous effects like DEPLOY or MERGE.
    """
    prompt = (
        f"You are approving the '{effect_name}' effect. "
        f"Type '{effect_name}' to confirm you understand the risk."
    )
    expected = effect_name
    challenge_id = _sign(f"{proposal_hash}:secondary:{expected}")

    return Challenge(
        challenge_id=challenge_id,
        prompt=prompt,
        expected=expected,
        proposal_hash=proposal_hash
    )
