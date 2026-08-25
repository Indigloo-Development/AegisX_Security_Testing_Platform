# AegisX V55 — Latest Release

# AegisX — Latest Build V55

## Version
- AegisX V55 — Modernized Commercial Build

## Frontend Stack
- Next.js 16.3.1
- React 19.2.8
- TypeScript 7.0.2
- @types/node 26.2.0
- @types/react 19.2.18
- @types/react-dom 19.2.4

## Backend Stack
- FastAPI 0.141.1
- SQLAlchemy 2.0.51
- Pydantic 2.13.4

## Security Modules
- Web Security / DAST
  - New Assessment
  - Authenticated Scan
  - CSP Analyzer
  - JWT Analyzer
- API Security
  - REST
  - GraphQL
  - gRPC
  - SOAP
  - Swagger/OpenAPI
  - JSON/Code Analysis
  - API Endpoint Discovery
- SCA / SBOM
- AI Security
  - LLM Security
  - RAG Security
  - Agent/MCP Security
  - AI Red Team
- Findings
- Issue Track Base
- Reports
- Continuous Monitoring / Security Operations foundations

## Direct Access / Standalone Mode
- No login / registration / OTP gate in direct-access mode.
- Standalone UI is available without PostgreSQL, Redis, Prometheus, Docker or Next.js dependencies.
- SQLite + local queue can be used for single-node standalone operation.

## Modernization
- Removed legacy active Next.js pages and duplicate wave-era UI components from the canonical route tree.
- Consolidated navigation into grouped Web/API/AI Security sections.
- Increased typography, spacing, controls and table readability.
- Refreshed standalone console visual system.
- Replaced deprecated Query.get and datetime.utcnow patterns in active backend paths.
- Removed stale TypeScript build-info artifacts from the release tree.

## Installation — Standalone Linux
```bash
./install.sh
./scripts/aegisx start
```
Open:
- http://127.0.0.1:3000
- http://127.0.0.1:8000/docs

For VirtualBox/VM shared folders, the installer uses a host-local virtualenv location to avoid symlink permission failures.

## Verification
- Backend pytest: 195 passed.
- Standalone UI gateway: HTTP 200 on / and /dashboard.
- TypeScript/TSX source transpile check: 34 source files, 0 parse diagnostics with the locally available TypeScript compiler.
- Full Next.js production build was not run because npm dependency installation was unavailable in the build environment.

## Important Accuracy Note
Security scanning is evidence-first and context-dependent. A heuristic indicator is not automatically treated as a confirmed exploit. CVSS values should be treated as normalized/context scores unless an official CVSS vector is available and validated.
