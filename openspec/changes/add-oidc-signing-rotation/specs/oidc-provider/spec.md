## ADDED Requirements

### Requirement: Signing-key rotation keeps an overlap and leaves the salt

The system SHALL publish a new Ed25519 signing public key in JWKS
before it signs an ID token with that key. ID tokens signed after
that cut SHALL use only the new key. The previous public key SHALL
remain in JWKS until 3600 seconds after it stopped signing, including
across a restart. The rotation path SHALL NOT read or write the
pairwise salt. It SHALL NOT rotate an XID or an Elect key.

#### Scenario: New tokens use the new key while the old key is still published

- GIVEN a signing key that has already signed an ID token
- WHEN rotation completes
- THEN JWKS contains the new public key and the previous public key
- AND an ID token minted after the cut has the new `kid`
- AND the pairwise salt bytes are unchanged

#### Scenario: The previous key leaves after the ID-token lifetime

- GIVEN a signing key that stopped signing 3600 seconds ago
- WHEN JWKS is served
- THEN the previous public key is absent
- AND the current public key is present

#### Scenario: A failed persist does not cut over

- GIVEN the retiring public key cannot be stored
- WHEN rotation is attempted
- THEN ID tokens are still signed by the key that was already current
