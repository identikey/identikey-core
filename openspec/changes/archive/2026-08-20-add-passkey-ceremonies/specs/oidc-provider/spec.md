## ADDED Requirements

### Requirement: Passkey assertion can finish /authorize

When a user completes WebAuthn assertion during `/authorize` with
valid PKCE, the system SHALL issue an authorization code to the
registered redirect for that account's XID. A WebAuthn assertion
SHALL NOT satisfy the URN grant.

#### Scenario: Assertion issues a code

- GIVEN a registered passkey on a stored XID and a valid authorize
  request with PKCE S256
- WHEN assertion verifies
- THEN a code is issued to the registered redirect
