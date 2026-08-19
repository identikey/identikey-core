## ADDED Requirements

### Requirement: URN grant accepts only identikey-auth Response

`/token` SHALL accept
`grant_type=urn:identikey:params:oauth:grant-type:challenge-response`
with an `identikey-auth` `Response`. It SHALL refuse a WebAuthn
assertion for this grant and SHALL NOT mint tokens in that case.
Every issued `sub` SHALL be computed by the existing `subject()`
seam. `identikey-oidc` SHALL NOT hold a user private key.

#### Scenario: Valid Response mints tokens

- GIVEN a stored XID and a valid `identikey-auth` Response for it
- WHEN `/token` is called with the URN grant
- THEN access and ID tokens are issued with `sub` from `subject()`

#### Scenario: WebAuthn assertion is refused

- GIVEN a WebAuthn assertion bound to a passkey on the account
- WHEN `/token` is called with the URN grant and that assertion
- THEN the request fails and no tokens are issued
