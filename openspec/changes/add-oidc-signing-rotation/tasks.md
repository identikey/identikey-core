# Tasks

- [x] Persist the retiring public key and the instant it stopped signing, separate from `pairwise.salt`
- [x] JWKS lists the current public key and the retiring public key until 3600 seconds after the cut, including after a restart
- [x] ID tokens minted after the cut use the new `kid` only
- [x] If the retiring key cannot be stored, the current signing key stays the signer
- [x] A test shows the pairwise salt bytes are unchanged across a successful rotation
- [x] A test shows the previous public key is absent from JWKS once the 3600 second window has passed

Out of scope: XID or Elect rotation, a user `credentials` row (`list_devices` / `revoke_device`), replacing josekit, JWT refresh tokens, and an admin UI.
