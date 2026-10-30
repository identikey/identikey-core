# Tasks

- [ ] Begin issues an email factor (32-byte secret) and an SMS factor (6 digits) and stores only SHA-256 of the challenge id concatenated with the secret
- [ ] Finish accepts the matching secret in constant time, consumes the factor, and returns `AccountRecoveryProof` tagged bootstrap or recover
- [ ] A wrong, expired, unknown, or consumed factor returns no proof; five wrong SMS attempts kill that factor
- [ ] `accept_bootstrap` runs only for a bootstrap proof and neither takes nor returns key bytes
- [ ] `accept_recover` runs only for a recover proof of a directory C1/C2 XID, and refuses C3/C4
- [ ] A bootstrap proof refuses recover, a recover proof refuses bootstrap, and `restore_key` still refuses `AccountRecoveryProof`
- [ ] `AccountRecoveryProof::granted` is not a successful factor check
- [ ] In-memory ports cover the cases; `identikey-server` gains no route

## Out of scope

- Mail and SMS transport, HTTP, and pages.
- Social re-verification, guardian recovery, and pre-rotation.
