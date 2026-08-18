## ADDED Requirements

### Requirement: Dev login is flag-gated and absent in production

When `IDENTIKEY_DEV_LOGIN` is exactly `1`, `/authorize` SHALL be able
to complete for an XID that already exists in the store. When the
variable is unset, that login path SHALL NOT be registered. The flag
SHALL NOT create accounts. `/health` SHALL NOT report the flag.

#### Scenario: Flag on issues a code

- GIVEN `IDENTIKEY_DEV_LOGIN=1` and a stored C2 identity
- WHEN `/authorize` is completed as that XID with valid PKCE
- THEN a code is issued to the registered redirect

#### Scenario: Flag off has no login path

- GIVEN `IDENTIKEY_DEV_LOGIN` is unset
- WHEN a client requests the dev-login path
- THEN the response is 404 and no code is issued
