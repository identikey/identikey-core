# Tasks

- [ ] Persist the retiring public key and the instant it stopped signing, separate from `pairwise.salt`
- [ ] JWKS lists the current public key and the retiring public key until 3600 seconds after the cut, including after a restart
- [ ] ID tokens minted after the cut use the new `kid` only
- [ ] If the retiring key cannot be stored, the current signing key stays the signer
- [ ] A test shows the pairwise salt bytes are unchanged across a successful rotation
- [ ] A test shows the previous public key is absent from JWKS once the 3600 second window has passed

Out of scope: XID or Elect rotation, replacing josekit, JWT refresh tokens, and an admin UI.
