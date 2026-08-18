## ADDED Requirements

### Requirement: One seam computes every token subject

Every OIDC `sub` SHALL be produced by a single function in
`identikey-oidc`. Pairwise clients SHALL receive
`KDF(salt, xid, sector)`. `public` clients SHALL receive the 64-hex
XID. The XID SHALL remain the internal key; a pairwise `sub` SHALL
NOT be used as a database primary key.

#### Scenario: Two sectors differ

- GIVEN one XID and two clients with distinct sector identifiers
- WHEN `sub` is computed for each
- THEN the two values differ and neither equals the XID hex

#### Scenario: Same sector is stable

- GIVEN one XID and one pairwise client
- WHEN `sub` is computed twice
- THEN the values are identical

#### Scenario: public is the XID

- GIVEN a client with `subject_type=public`
- WHEN `sub` is computed
- THEN the value is the 64-lowercase-hex XID
