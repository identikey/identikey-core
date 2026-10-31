# add-passkey-counter-policy

## Rule

Read the authenticator's counter only after the assertion signature
has verified.

- Counter is 0. Accept. Do not log a regression or a drop. Leave a
  higher stored value where it is. `last_used_at` still advances.
- Counter is greater than the stored value. Accept and store it.
  `last_used_at` advances.
- Counter is greater than 0 and less than the stored value. Accept.
  Log the credential id, the stored value, and the presented value.
  Do not write the lower value. `last_used_at` still advances.
- Counter is greater than 0 and equal to the stored value. Reject
  with the existing "sign counter did not increase" failure. The
  encapsulation path keeps its invalid-proof failure. This is the
  clone signal. A single-use challenge already stops replay of one
  assertion.

"Goes backwards" is the third bullet. An equal positive counter is
not that case. The 2026-09-26 note did not accept it.

## Sites

`finish_assert`, `finish_managed_assert`, and the passkey branch in
`identikey-keys` encapsulation. One helper, so a later call site
cannot keep the old reject. The log is server-side. The page copy
does not change.

## Store write

Every accepted assertion writes one update:
`sign_counter = GREATEST(sign_counter, presented)` and
`last_used_at = now()`. A drop and a zero still bump `last_used_at`.
The hosted and managed paths read the counter without a row lock, so
the `GREATEST` is what keeps a slower concurrent write from lowering
the floor. The encapsulation path already holds `FOR UPDATE`. Do not
skip the update on a drop: `/account` shows `last_used_at`.

## Library counter

webauthn-rs 0.5.4 rejects a presented counter at or below the counter
inside the `Passkey`, when either value is nonzero. `passkey_json` is
not updated after registration. Before `finish_passkey_authentication`
and `finish_discoverable_authentication`, the `Passkey` those calls
see has its counter set to 0. Do that in `load_passkeys`, on the
discoverable key, and on the state stored for managed and
encapsulation ceremonies. Do not call `Passkey::update_credential`.
That would raise the library's floor and turn the next drop into a
reject. The column remains the only counter authority.
