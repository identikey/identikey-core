# add-a1-account-recovery

## Where it lives

`identikey-recovery` grows the A1 ceremony beside the existing marker
types. The crate still does not implement guardian reconstruction.
`identikey-server` gains no route. Nothing in this change dials a
carrier.

The caller supplies a clock, a destination directory, and a factor
store. Tests use in-memory ports. Production wiring of those ports is
the later route change.

## Factors

Begin takes a destination, a purpose (`bootstrap` or `recover`), and an
expiry. It returns a challenge id and the secret the caller will send.

- Email secret: 32 random bytes.
- SMS secret: six decimal digits.

The store keeps SHA-256 of the challenge id concatenated with the
secret. It does not keep the secret. Finish compares the presented
bytes to that hash in constant time.

A recover begin also takes the XID the directory binds to that
destination. The directory reports the rung. Begin fails when the
destination is unbound, or when the rung is C3 or C4.

A bootstrap begin has no XID.

## Finish

Success consumes the factor, then returns the proof.

The proof names the purpose. A recover proof also names the XID. It
does not name a rung, a secret, or any key bytes.

- Wrong secret: no proof. An SMS factor counts the attempt and is dead
  after five wrong attempts. An email factor stays open until expiry
  or success.
- Expired, unknown, or already consumed: no proof, and a consumed
  factor stays consumed.
- Recover when the directory now says C3 or C4: no proof, even if the
  secret matches. The factor is not consumed by that refusal.

`AccountRecoveryProof::granted` is not a successful factor check. The
production constructor is finish. The unchecked constructor comes off
the public API.

## What the proof allows

`accept_bootstrap` runs the caller's create closure only for a
bootstrap proof. It does not take a `managed_key_blob` and it does not
return one. The closure is where the existing `create_managed` sits,
in the later route.

`accept_recover` runs the caller's enroll closure only for a recover
proof whose XID is the one in the proof, and only when the directory
still says C1 or C2. The closure is the existing passkey enrollment,
not a new WebAuthn stack.

A bootstrap proof refuses `accept_recover`. A recover proof refuses
`accept_bootstrap`. `restore_key` still refuses `AccountRecoveryProof`.
`restore_access` still returns `ManagedAccess` and no key bytes.

## What this does not choose

The transport vendor, the page, and the route shape. The length of the
expiry. Which managed rung a bootstrap closure picks, beyond the rung
check `create_managed` already has.
