## ADDED Requirements

### Requirement: Email and SMS factors

The account-recovery library SHALL issue an email factor and an SMS
factor for a destination and a purpose of `bootstrap` or `recover`.
The email secret SHALL be 32 bytes. The SMS secret SHALL be six decimal
digits. The factor store SHALL keep only SHA-256 of the challenge id
concatenated with the secret. Finish SHALL compare a presentation to
that hash in constant time. The library SHALL NOT send email or SMS.
The caller SHALL supply the clock used for expiry.

#### Scenario: Email factor is stored as a hash

- GIVEN a bootstrap begin for an email destination and an expiry in the future
- WHEN the factor is issued
- THEN the returned secret is 32 bytes and the stored value equals SHA-256 of the challenge id concatenated with that secret

#### Scenario: SMS factor is six digits

- GIVEN a bootstrap begin for a phone destination
- WHEN the factor is issued
- THEN the returned secret is six decimal digits and the stored value is not that secret

### Requirement: Success returns an account-recovery proof

On a matching unexpired secret, finish SHALL consume the factor before
returning `AccountRecoveryProof`. The proof SHALL name the purpose. A
recover proof SHALL also name the XID. The proof SHALL NOT contain the
secret or any key bytes. `AccountRecoveryProof::granted` SHALL NOT
count as a successful factor check.

#### Scenario: Matching email secret

- GIVEN a live email factor for purpose bootstrap
- WHEN finish is called with that secret
- THEN the factor is consumed and the proof's purpose is bootstrap

#### Scenario: Matching SMS secret on an existing account

- GIVEN a live SMS factor for purpose recover bound to a C1 or C2 XID
- WHEN finish is called with that secret
- THEN the proof names recover and that XID

### Requirement: Failure and replay return no proof

A wrong secret, an expired factor, an unknown factor, and a consumed
factor SHALL NOT return a proof. A wrong SMS secret SHALL count one
attempt, and the fifth wrong attempt SHALL kill that factor. A wrong
email secret SHALL leave the factor open until expiry or success. A
consumed factor SHALL stay consumed.

#### Scenario: Wrong SMS secret

- GIVEN a live SMS factor
- WHEN finish is called with a different six-digit secret
- THEN no proof is returned and the factor still accepts the original secret

#### Scenario: Fifth wrong SMS attempt

- GIVEN an SMS factor with four wrong attempts already counted
- WHEN finish is called with another wrong secret
- THEN no proof is returned and the original secret also fails

#### Scenario: Replayed success

- GIVEN a factor that has already finished successfully
- WHEN finish is called again with the same secret
- THEN no proof is returned

### Requirement: Bootstrap and recovery authorize different calls

`accept_bootstrap` SHALL invoke the caller closure only for a bootstrap
proof, and SHALL NOT take or return key bytes. `accept_recover` SHALL
invoke the caller closure only for a recover proof whose XID is the
proof's XID and whose directory rung is C1 or C2. A bootstrap proof
SHALL refuse `accept_recover`. A recover proof SHALL refuse
`accept_bootstrap`. The directory, not the request, SHALL supply the
rung.

#### Scenario: Bootstrap runs create and not enroll

- GIVEN a bootstrap proof
- WHEN `accept_bootstrap` is called with a create closure
- THEN the closure runs once and its result contains no key bytes

#### Scenario: Recover runs enroll

- GIVEN a recover proof for a XID the directory reports as C2
- WHEN `accept_recover` is called with an enroll closure for that XID
- THEN the closure runs once

#### Scenario: C3 recover is refused

- GIVEN a destination whose directory rung is C3 and a secret that matches a factor for that destination
- WHEN finish is called
- THEN no proof is returned

#### Scenario: Cross-purpose calls fail

- GIVEN a bootstrap proof and a recover proof
- WHEN `accept_recover` is called with the bootstrap proof and `accept_bootstrap` is called with the recover proof
- THEN neither caller closure runs

### Requirement: An account-recovery proof is not key recovery

`restore_key` SHALL refuse `AccountRecoveryProof`. `restore_access`
SHALL accept that proof and SHALL NOT return key bytes.

#### Scenario: Proof does not restore a key

- GIVEN an `AccountRecoveryProof` from a successful finish
- WHEN `restore_access` is called with it
- THEN the result is managed access and no API on that proof yields key bytes
