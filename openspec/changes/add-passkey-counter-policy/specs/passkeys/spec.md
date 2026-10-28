## ADDED Requirements

### Requirement: A synced passkey counter may drop

A verified passkey assertion SHALL be accepted when its sign counter
is 0. A verified assertion SHALL be accepted when its sign counter is
greater than 0 and lower than the stored counter. That lower value
SHALL be logged and SHALL NOT replace the stored counter. A sign
counter greater than 0 and equal to the stored counter SHALL still
fail. A higher counter SHALL replace the stored counter. This rule
SHALL apply to hosted assertion, managed assertion, and the
encapsulation verifier.

#### Scenario: A lower counter still signs in

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 4
- THEN the ceremony succeeds
- AND the stored counter remains 10
- AND the server logs the drop

#### Scenario: Zero is not a regression

- GIVEN a stored passkey whose counter is 0
- WHEN a verified assertion presents counter 0
- THEN the ceremony succeeds
- AND no regression is logged

#### Scenario: A repeated positive counter fails

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 10
- THEN the ceremony fails
- AND the stored counter remains 10
