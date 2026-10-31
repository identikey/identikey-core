# Tasks

- [x] Spike `password-hasher` before any implementation. Finding: `docs/spikes/password-hasher/finding.md` (go, Argon2id m=19456 KiB, t=2, p=1).
- [x] Attach a password to an existing account as a credentials row whose secret is an Argon2id PHC string (m=19456, t=2, p=1).
- [x] List and revoke that row with the other devices.
- [x] Password login uses authorization-code plus PKCE and resolves to the same XID as the account's passkey.
- [x] An A0 password proof does not consent to C2 signing. No resource-owner password grant, no signup, and no reset.
