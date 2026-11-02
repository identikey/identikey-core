## ADDED Requirements

### Requirement: Apple identity token verification

The social-id crate SHALL verify a compact Apple identity token with
RS256 against Apple's JWKS. It SHALL accept only issuer
`https://appleid.apple.com`. It SHALL require a caller-supplied
audience and reject any other audience. It SHALL reject an expired
token beyond a 5 second skew, a non-RS256 algorithm, and a signature
that does not match the JWKS. On success it SHALL return `sub`, and
`email`, `email_verified`, and `is_private_email` when those claims
are present.

#### Scenario: Valid Apple token

- GIVEN a pinned Apple JWKS and an RS256 token with the pinned issuer, the caller's audience, a live expiry, and a `sub`
- WHEN the token is verified as Apple
- THEN verification succeeds and the returned `sub` is the token's `sub`

#### Scenario: Apple email may be absent

- GIVEN a valid Apple token with no email claims
- WHEN the token is verified
- THEN verification succeeds and no email is returned

#### Scenario: Wrong Apple audience

- GIVEN a valid Apple token whose audience is not the caller's
- WHEN the token is verified
- THEN verification fails

### Requirement: Google identity token verification

The social-id crate SHALL verify a compact Google identity token with
RS256 against Google's JWKS. It SHALL accept issuer
`https://accounts.google.com` or `accounts.google.com` and reject any
other issuer. It SHALL require a caller-supplied audience. It SHALL
reject an expired token beyond a 5 second skew, a non-RS256
algorithm, and a bad signature. On success it SHALL return `sub`, and
`email`, `email_verified`, `name`, and `picture` when present.

#### Scenario: Valid Google token

- GIVEN a pinned Google JWKS and an RS256 token with issuer `https://accounts.google.com`, the caller's audience, a live expiry, and a `sub`
- WHEN the token is verified as Google
- THEN verification succeeds and the returned `sub` is the token's `sub`

#### Scenario: Google issuer without a scheme

- GIVEN a token that is otherwise valid and whose issuer is `accounts.google.com`
- WHEN the token is verified as Google
- THEN verification succeeds

#### Scenario: Wrong Google issuer

- GIVEN a token signed by the pinned Google key whose issuer is neither accepted Google issuer
- WHEN the token is verified as Google
- THEN verification fails

### Requirement: Provider JWKS cache

The crate SHALL cache Apple's JWKS from
`https://appleid.apple.com/auth/keys` and Google's JWKS from
`https://www.googleapis.com/oauth2/v3/certs` separately. A token whose
`kid` is already cached SHALL NOT cause a fetch. A token whose `kid`
is not cached SHALL fetch that provider's JWKS once and search again.
If the `kid` is still absent, or the fetch fails, verification SHALL
fail.

#### Scenario: Cached kid does not refetch

- GIVEN the provider cache already holds the token's `kid`
- WHEN the token is verified
- THEN no JWKS request is made

#### Scenario: Unknown kid refreshes once

- GIVEN the cache does not hold the token's `kid` and one fetch would return a document that does
- WHEN the token is verified
- THEN that provider's JWKS is fetched once and verification uses the new document

#### Scenario: Kid still missing after refresh

- GIVEN a fetch returns a document that still lacks the token's `kid`
- WHEN the token is verified
- THEN verification fails and no second fetch is made
