# add-passkey-counter-policy

## Rule

Read the authenticator's counter only after the assertion signature
has verified.

- Counter is 0. Accept. Do not log a regression. The stored value
  may already be 0; writing 0 again is harmless.
- Counter is greater than the stored value. Accept and store it.
- Counter is greater than 0 and less than the stored value. Accept.
  Log the credential id, the stored value, and the presented value.
  Do not write the lower value.
- Counter is greater than 0 and equal to the stored value. Reject
  with the existing "sign counter did not increase" failure. The
  encapsulation path keeps its invalid-proof failure.

"Goes backwards" is the third bullet. An equal positive counter is
not that case. The 2026-09-26 note did not accept it.

## Sites

`finish_assert`, `finish_managed_assert`, and the passkey branch in
`identikey-keys` encapsulation. One helper, so a later call site
cannot keep the old reject. The log is server-side. The page copy
does not change.
