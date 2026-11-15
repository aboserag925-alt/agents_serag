# Security status and deployment requirements

## Changes in this branch

- Authentication token verification now fails closed when the server token is absent.
- No embedded default token is accepted.
- The `dev-bypass` token is rejected.
- Token comparison uses constant-time `hmac.compare_digest`.
- The in-memory rate limiter is protected by a thread lock.
- Unit tests cover missing, incorrect, bypass, and valid bearer tokens.

## Important remaining blockers

This change hardens the shared token verifier only. It does **not** yet establish complete application authentication.

Before exposing the service publicly, a follow-up change must:
1. Apply authentication consistently to every task, approval, audit, agent, log, secrets, and administrative HTTP route.
2. Authenticate WebSocket connections before accepting them.
3. Provide a safe browser session/login mechanism; do not embed the server token in frontend JavaScript.
4. Restrict CORS to explicitly configured trusted origins and disallow wildcard origins with credentials.
5. Replace shell command execution with validated argument arrays and explicit executable allowlists.
6. Implement actual Infisical secret retrieval, scoped by environment and secret path; a successful login alone is not sufficient.
7. Add integration tests for protected routes and WebSocket authorization.

## Required runtime configuration

Set a high-entropy `HUB_AUTH_TOKEN` through the deployment secret manager. Never commit its value. If it is absent, protected operations intentionally fail closed.

## Verification

Run:

```bash
python -m unittest discover -s tests -v
```

These tests must be executed in the target environment before declaring the change verified. This repository edit alone is not evidence of a passing runtime test.
