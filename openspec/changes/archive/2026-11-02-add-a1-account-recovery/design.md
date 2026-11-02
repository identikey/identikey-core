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

## Store transition

The factor store applies one conditional transition for finish. It
reads live state, expiry, the attempt budget, and consumption
together, and it commits the new state before a proof exists. Two
matching finishes produce one proof. A store error produces none.
A wrong SMS attempt and a matching finish on the same factor have
one winner: if the committed state is the fifth failure, no proof
is issued; if the committed state is consumption, the proof is
issued and the failure is not. Wrong attempts stay recorded after
a failed write is not the way they persist: a failed attempt write
does not increment the budget.

## Binding

Begin asks the directory. The directory result is the trusted
binding: channel, destination, purpose, and, for recover, the XID
and the rung. That binding is immutable on the factor. A caller-
supplied XID that disagrees with the directory is refused at begin.
If the destination is unbound or rebound before finish, finish
refuses and does not consume a recover factor whose directory XID
no longer matches. Finish does not freeze destination authority.
`accept_recover` checks the directory again. If that destination is
gone or now belongs to another XID, acceptance refuses and consumes
the proof. The current-custody check and single use still apply.
Acceptance callbacks are trusted integration
code and must use the XID and destination the library passes them.
A bootstrap proof proves possession of the destination that began
it. It does not verify some other address the callback invents.

## Proof lifetime

Finish returns one proof. Acceptance consumes that proof. A second
`accept_bootstrap` or `accept_recover` on it does not run the
closure. If the closure returns an error, the proof stays consumed.
`AccountRecoveryProof::granted` is not public. `restore_access` on
this proof does not authorize managed access and does not bypass
`accept_bootstrap` or `accept_recover`. `restore_key` still refuses
the proof.

## Generation

Email secrets and SMS digits come from a cryptographic generator.
Six digits are sampled without bias and may include leading zeros.
A challenge id collision does not overwrite a live factor or reset
its attempt count. Entropy failure or insertion failure returns no
factor and no secret. The hash input is the challenge id bytes
followed by the secret bytes, with those lengths unambiguous.
