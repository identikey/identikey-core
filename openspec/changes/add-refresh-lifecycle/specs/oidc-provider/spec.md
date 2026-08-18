## ADDED Requirements

### Requirement: Refresh tokens are hashed, rotated, and revocation-checked

The system SHALL persist only a SHA-256 hash of each refresh token.
A successful refresh SHALL issue a new refresh token and invalidate
the previous one. A revoked refresh token SHALL be rejected at both
the token endpoint (refresh grant) and `/introspect`.

#### Scenario: Rotation kills the old token

- GIVEN a valid refresh token T1
- WHEN `/token` is called with T1
- THEN a new refresh token T2 is returned and a later refresh with
  T1 fails

#### Scenario: Revoke is honoured on introspect

- GIVEN a refresh token that has been revoked
- WHEN `/introspect` is called with it
- THEN the response is inactive
