# add-oidc-signing-rotation

> **PENDING**

Bead `identikey-core-ccf.13`, extracted from `identikey-core-ccf.9`.
Preparation 2026-10-28: `SigningKey` holds one Ed25519 JWK and
`public_jwks` publishes that one key. `sign_id_token` is the only
JWT signer. Access tokens are `random_token` and refresh tokens are
stored as a hash, so they are not checked through JWKS. ID-token
lifetime is `ACCESS_TTL` (3600 seconds). `PairwiseSalt` lives in
`pairwise.salt` and its module says it is never rotated. Outcome:
new contract. Authority: none. The post-quantum campaign grant does
not cover this node. Activation stays off.

## Why

Relying parties cache the OP's signing key. Replacing it in one step
makes every unexpired ID token fail verification. The pairwise salt
sits next to that key on disk. A rotation that treats "the material
in the data directory" as one secret would change every pairwise
`sub` at every relying party.

## What

- Capability `oidc-provider`.
- Rotation publishes the new public key in JWKS before any ID token
  is signed with it.
- New ID tokens use only the new key.
- The previous public key stays in JWKS until 3600 seconds after it
  stopped signing.
- The retiring record is the public key. The old private key is not
  required once signing has moved.
- The pairwise salt bytes and `pairwise.salt` are not on this path.
- XID and Elect rotation are a different system.

## Impact

- Capabilities: MODIFIED `oidc-provider` (one added requirement).
  The living "Discovery and JWKS" requirement stays as it is.
- ADRs: none.

## User journey & surfaces

No new UI because a relying party already fetches
`/.well-known/jwks.json` and validates an ID token. During the
overlap that document lists two keys. After the overlap it lists the
current one. A person signing in does not see a new page. An
ID token minted before the cut still verifies until it expires.

Working: JWKS shows the new key and the previous public key, and a
new login's `kid` is the new one.

Empty: a server that has never rotated still publishes one key, as
it does now.

Failed: a rotation that cannot persist the retiring public key does
not start signing with the new key.

Off: there is no flag that rotates the salt. The salt API does not
grow a rotate operation.

## Out of scope

- Rotating a user's XID, Elect key, or ML-DSA control key.
- Choosing a replacement for josekit (`identikey-core-ccf.10`).
- Making refresh tokens into JWTs.
- A hosted button that an operator clicks. The contract is the
  overlap rule, not an admin UI.
