## ADDED Requirements

### Requirement: Pairwise sector is registered, not derived

A pairwise client's sector identifier SHALL be part of its registration,
for both the primary client and clients in `IDENTIKEY_CLIENTS`, and SHALL be
the only sector input to its `sub`. The configured value SHALL reach the
subject function byte-for-byte, without trimming or normalization. Client
construction at boot and request time SHALL NOT derive a sector from a
redirect URI; only the operator preflight MAY compute the legacy derived
value, and only to compare it. The system SHALL refuse to start when a
pairwise client's sector is missing or empty, naming that client. A public
client SHALL NOT require a sector.

#### Scenario: Redirects change, identity does not

- GIVEN a pairwise client with sector `taskmaster.dev` and one redirect
- WHEN a redirect on another host is added before it, or the original redirect is replaced or removed
- THEN the `sub` for a given XID is unchanged

#### Scenario: Pinned legacy value preserves today's subject

- GIVEN a pairwise client whose pin equals the sector previously derived from its first merged redirect
- WHEN `sub` is computed for a given XID and salt
- THEN it equals the `sub` the previous derivation produced

#### Scenario: Missing sector refuses boot

- GIVEN a pairwise client registered with no sector or an empty one
- WHEN the server starts
- THEN startup fails and the error names that client

#### Scenario: Public client needs no sector

- GIVEN a client with `subject_type=public` and no sector
- WHEN the server starts
- THEN it starts and that client's `sub` is the base58btc XID

### Requirement: Client preflight compares pins with legacy sectors

The system SHALL provide an operator preflight that loads the complete
client configuration through the boot loader and reports, for each client,
its id, configuration source, subject type, pinned sector, and legacy
derived sector. It SHALL NOT output client secrets. It SHALL exit with
failure when the loader refuses the configuration or any pairwise client's
pin differs from its legacy value.

#### Scenario: Mismatched pin fails preflight

- GIVEN a pairwise client whose first redirect host is `taskmaster.dev` and whose pin is `www.taskmaster.dev`
- WHEN the preflight runs
- THEN it exits with failure and names that client

#### Scenario: Complete matching configuration passes

- GIVEN every pairwise client pinned to its legacy sector and every public client without one
- WHEN the preflight runs
- THEN it exits successfully and prints no secret
