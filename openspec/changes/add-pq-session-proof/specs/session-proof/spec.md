## ADDED Requirements

### Requirement: One control signature opens a session

The system SHALL open a session only when the cited state digest
resolves to the current unforked head for that XID and the opening
carries one verifying ML-DSA-65 signature by that head's control key.
The signed opening SHALL commit the domain `identikey-pq-session/v1`,
the XID, the 32-byte state digest, an audience, and a fresh 32-byte
challenge. A classical signature SHALL NOT open a session. A forked
chain SHALL NOT open a session. The proof SHALL name the XID and
SHALL NOT name a classical fingerprint.

#### Scenario: The current control key opens a session

- GIVEN an unforked head whose control key is ML-DSA-65
- WHEN an opening for that XID and that head's digest verifies under that key
- THEN a session exists for that audience and digest

#### Scenario: A classical signature does not open a session

- GIVEN an unforked head
- WHEN the opening is signed only by a classical key
- THEN no session exists

### Requirement: A later proof is a session MAC

A proof after opening SHALL verify as HMAC-SHA-256 under the 32-byte
session key over the audience, the state digest, and the message.
Verification SHALL NOT require a second public-key signature. A proof
whose audience or state digest differs from the opening SHALL fail.
The verifier SHALL NOT append the proof to a log. Any holder of the
session key SHALL be able to produce a proof that verifies.

#### Scenario: The follow-up check needs no public key

- GIVEN a session opened for an audience and a state digest
- WHEN a follow-up proof is the HMAC of that audience, that digest, and a message under the session key
- THEN the proof verifies and no public-key signature is checked

#### Scenario: Another audience fails

- GIVEN a session opened for one audience
- WHEN a follow-up proof names a different audience
- THEN the proof fails

#### Scenario: An older digest fails

- GIVEN a session opened for one state digest
- WHEN a follow-up proof names a different digest
- THEN the proof fails
