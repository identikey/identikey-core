# Design — dev authorize login

Sensitive. One env flag, fail closed.

- `IDENTIKEY_DEV_LOGIN` must be the exact value `1` (not any
  non-empty string).
- The XID must already exist in `KeysStore`. No implicit signup.
- Never compile the form into a path that is registered when the
  flag is off (not “registered but returns 403”).
- `/health` still does not mention the flag or key state.
