## ADDED Requirements

### Requirement: Pairwise export reproduces issued subjects

A user’s export SHALL include enough material for a successor OP to
recompute every pairwise `sub` already issued for that user. A test
SHALL prove that `sub()` over the export matches the values previously
returned to clients. Export SHALL NOT write the salt to logs.

#### Scenario: Successor matches issued sub

- GIVEN a pairwise `sub` S issued to client C for XID H
- WHEN a successor computes `sub` from the user’s export for C
- THEN the result equals S
