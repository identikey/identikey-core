# Design — OIDF suite as instrument

Property: Basic OP and Config OP are green against 127.0.0.1.

- Image/source: GitLab `openid/conformance-suite` (MIT).
- Do not vendor the Java tree into this repo if a prebuilt image
  exists; pin a digest.
- `run-test-plan.py` is the CI entry (OIDF’s own script).
- Server under test boots with generated salt + signing key +
  `IDENTIKEY_DEV_LOGIN=1` and a pre-seeded C2 user.
- A red job is success of the instrument until the code flow lands;
  do not `continue-on-error`.
