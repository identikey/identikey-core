# add-account-key-model

## Decided

A `credentials` row is the device record. `list_devices` returns
non-revoked rows. `revoke_device` sets `revoked_at` under the account
lock. That requirement is already living. Kinds observed in the
schema are `passkey`, `oidc_apple`, `oidc_google`, `identikey_auth`,
and `ssh_git`.

`accounts.email` is a column on the account. It is the address an A1
ceremony writes. It is not listed and not revoked as a device.

`managed_key_blob` is the server-held Ed25519 operational Sign key.
The account may show its public key later (`add-managed-key-visibility`).
That display is not a device row and has no revoke control on this
model. Schnorr blobs from before the Ed25519 cutover stay unusable
for the responder. This change does not export or rotate the blob.

A0 and A1 proofs restore or attach access. They do not authorize use
of the operational Sign key and they do not mint Elect.

The OP signing key and the pairwise salt belong to the provider.
They are not rows on a user's account.

Surviving access counts a non-revoked `passkey`, `oidc_apple`,
`oidc_google`, `identikey_auth`, or password credentials row. It
does not count `ssh_git`, `accounts.email`, or `managed_key_blob`.
`revoke_device` stays the unconditional primitive, including a
sole passkey, and the living "Revoke hides the device" scenario
stays about that primitive. Account-access revocation is the
kind-generic operation that enforces the count. It decides and
revokes in one account-scoped critical section, custody row
before credential row. Another counted row makes the revoke
ordinary. The last counted row stays unless the caller passes an
explicit last-access confirmation. `identikey-core-zlf.6` owns
that operation for every counted kind and verifies the concurrent
case. This model fold does not claim the store already enforces
the rule. Astra sent this boundary back on 2026-10-31; the delta
now states it. Fresh advise follows. The reader is Astra. Grok
is the author vendor.

## Open

None on this node. Password stays on `identikey-core-zlf.9`, with
the hasher spike still unverified. A recovery-enrolled passkey is an
ordinary passkey on `identikey-core-zlf.2`. Neither rule is a
requirement of this change.
