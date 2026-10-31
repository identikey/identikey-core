## ADDED Requirements

### Requirement: A synced passkey counter may drop

A verified passkey assertion SHALL be accepted when its sign counter
is 0, including when the stored counter is already positive. That
acceptance SHALL NOT lower the stored counter and SHALL NOT be logged
as a regression or a drop. A verified assertion SHALL be accepted
when its sign counter is greater than 0 and lower than the stored
counter. That lower value SHALL be logged and SHALL NOT replace the
stored counter. A sign counter greater than 0 and equal to the stored
counter SHALL still fail. That failure is the clone signal. A higher
counter SHALL replace the stored counter. Every accepted assertion
SHALL set `last_used_at` to the current time and SHALL leave
`sign_counter` at the greater of the stored value and the presented
value.

This rule SHALL apply to hosted assertion, managed assertion, and the
encapsulation verifier. Before webauthn-rs checks the assertion, the
counter inside the `Passkey` it sees SHALL be 0, so the library's own
counter check does not reject the ceremony. `credentials.sign_counter`
and this rule SHALL be the only counter authority. The counter stored
in `passkey_json` SHALL NOT be raised after registration.

#### Scenario: A lower counter still signs in

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 4
- THEN the ceremony succeeds
- AND the stored counter remains 10
- AND the server logs the drop
- AND `last_used_at` advances

#### Scenario: Zero over a positive counter is not a reset

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 0
- THEN the ceremony succeeds
- AND the stored counter remains 10
- AND no regression and no drop is logged
- AND `last_used_at` advances

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

#### Scenario: A registration counter above zero does not reject a later drop

- GIVEN a passkey whose `passkey_json` was registered at counter 5 and whose stored counter is 5
- WHEN a verified assertion presents counter 4
- THEN webauthn-rs does not reject the assertion for the counter
- AND the ceremony succeeds
- AND the stored counter remains 5
- AND the server logs the drop
