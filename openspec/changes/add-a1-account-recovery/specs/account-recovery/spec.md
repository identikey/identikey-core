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
- WHEN `restore_key` is called with it
- THEN the call is refused
- AND `restore_access` on that proof does not authorize managed access

### Requirement: Factor consumption is one committed transition

The factor store SHALL decide expiry, the attempt budget, and
consumption in one conditional transition. Only a committed
consumption SHALL produce a proof. A store error SHALL produce no
proof. Two concurrent matching finishes of one factor SHALL produce
one proof. A concurrent wrong SMS attempt and a matching finish
SHALL have one committed winner. The fifth committed failure SHALL
produce no proof. A failed attempt write SHALL NOT increment the
budget.

#### Scenario: Two matching finishes

- GIVEN one live factor
- WHEN two finishes present the matching secret concurrently
- THEN one proof is returned and the factor is consumed

#### Scenario: Fifth failure wins the race

- GIVEN an SMS factor with four wrong attempts recorded
- WHEN a wrong finish and a matching finish commit, and the committed state is the fifth failure
- THEN no proof is returned

### Requirement: The directory binds the factor

Begin SHALL take the destination binding from the directory. The
factor SHALL record channel, destination, purpose, and, for recover,
the directory XID. A caller-supplied XID that differs SHALL be
refused. Finish SHALL refuse a recover factor whose directory
binding no longer matches, and SHALL NOT consume it for that
refusal. Acceptance callbacks SHALL receive the bound destination
and, for recover, the bound XID. A bootstrap proof SHALL prove the
destination that began it. `accept_recover` SHALL check the
directory again. If the destination is unbound or bound to a
different XID, acceptance SHALL refuse and SHALL consume the proof.
The current-custody check SHALL still apply.

#### Scenario: A supplied XID cannot retarget recovery

- GIVEN a destination the directory binds to XID A
- WHEN begin is asked to recover XID B
- THEN no factor is issued

#### Scenario: Removal after finish consumes the proof

- GIVEN a recover proof for destination D and XID A, and A is still C2
- WHEN D is no longer bound to A and `accept_recover` is called
- THEN the closure does not run and the proof is consumed

#### Scenario: Reassignment after finish consumes the proof

- GIVEN a recover proof for destination D and XID A, and A is still C2
- WHEN the directory binds D to XID B and `accept_recover` is called
- THEN the closure does not run and the proof is consumed

#### Scenario: A rebound destination does not finish

- GIVEN a recover factor bound to XID A
- WHEN the directory now binds that destination to XID B and finish presents the matching secret
- THEN no proof is returned and the factor is not consumed

### Requirement: Acceptance consumes the proof

`accept_bootstrap` and `accept_recover` SHALL consume the proof. A
second acceptance SHALL NOT run the closure. A closure error SHALL
leave the proof consumed. `AccountRecoveryProof::granted` SHALL NOT
be a public constructor. `restore_access` SHALL NOT turn this proof
into an authorization that bypasses those functions.

#### Scenario: A second acceptance does not run

- GIVEN a bootstrap proof that `accept_bootstrap` has already consumed
- WHEN `accept_bootstrap` is called again
- THEN the closure does not run

### Requirement: Secrets are unpredictable

Email secrets and SMS digits SHALL come from a cryptographic
generator. SMS digits SHALL be an unbiased sample of six decimal
digits, including leading zeros. A challenge id collision SHALL NOT
overwrite a live factor or reset its attempt count. Entropy failure
or insertion failure SHALL return no factor.

#### Scenario: Insertion failure issues nothing

- GIVEN the factor store rejects the insert
- WHEN begin runs
- THEN no challenge id and no secret are returned
