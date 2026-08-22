## ADDED Requirements

### Requirement: Authorize login is the passkey page

When `IDENTIKEY_DEV_LOGIN` is unset, completing `/authorize` SHALL
send the user to `/authorize/passkey`. That page SHALL be the
production login surface.

#### Scenario: Authorize redirects to the passkey page

- GIVEN a registered public client and valid PKCE
- WHEN `GET /authorize` is called
- THEN the response redirects to `/authorize/passkey`
- AND that page is HTML for assertion, not the flag-gated dev form
