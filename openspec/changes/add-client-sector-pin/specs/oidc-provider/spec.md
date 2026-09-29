## ADDED Requirements

### Requirement: Pairwise sector is registered, not derived

A pairwise client's sector identifier SHALL be part of its registration and
SHALL be the only sector input to its `sub`. The system SHALL NOT derive a
sector from a redirect URI. The system SHALL refuse to start when a pairwise
client has no sector, naming that client. A public client SHALL NOT require
a sector.

#### Scenario: Redirects change, identity does not

- GIVEN a pairwise client with sector `taskmaster.dev` and one redirect
- WHEN a redirect on another host is added before the existing one
- THEN the `sub` for a given XID is unchanged

#### Scenario: Missing sector refuses boot

- GIVEN a pairwise client registered without a sector
- WHEN the server starts
- THEN startup fails and the error names that client

#### Scenario: Public client needs no sector

- GIVEN a client with `subject_type=public` and no sector
- WHEN the server starts
- THEN it starts and that client's `sub` is the base58btc XID
