# contribution-policy

Living truth for the product-tier contribution license. Folded from
`add-product-cla-scope` (2026-09-24).

### Requirement: Product CLA is a license and not a protocol gate

A contribution to the product tier SHALL be accepted under a
licensing CLA in which the contributor keeps copyright. That CLA
SHALL grant Identikey Inc. and its successors the right to include
the contribution in commercially licensed releases of the product.
It SHALL NOT be an assignment of copyright. It SHALL NOT be required
for a contribution to identikey-protocol.

#### Scenario: Product pull request

- GIVEN a contribution to identikey-core
- WHEN it is accepted
- THEN the contributor still holds copyright in that contribution
- AND Identikey Inc. may include it in a commercial release of the product

#### Scenario: Protocol pull request

- GIVEN a contribution to identikey-protocol
- WHEN the author has not signed the product CLA
- THEN the missing product CLA is not a reason to reject it
