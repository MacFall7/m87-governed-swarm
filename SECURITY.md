# Security Policy

## Reporting a Vulnerability

If you believe you've found a security vulnerability in M87 Governed Swarm, please report it privately rather than opening a public issue.

- Email: security@m87studio.net
- - Include: affected component (API, Runner, adapter, UI), reproduction steps, and impact assessment.
  - - Response target: acknowledgment within 5 business days.
   
    - Please do not open a public GitHub issue for suspected vulnerabilities until a fix is available.
   
    - ## Scope
   
    - This policy covers the governance perimeter documented in the README (Runner enforcement, DEH verification, Phase 3-6 API governance) and the UI's fail-closed normalization boundary.
   
    - See also:
    - - [Threat Model](docs/THREAT_MODEL.md)
      - - [Security Controls Matrix](docs/SECURITY_CONTROLS_MATRIX.md)
        - - [Dependency Audit](docs/DEPENDENCY_AUDIT.md)
         
          - ## Supported Versions
         
          - This project is under active development (V1, Phase 3-6 governance). Security fixes land on `main`; there is no separate LTS branch at this time.
          - 
