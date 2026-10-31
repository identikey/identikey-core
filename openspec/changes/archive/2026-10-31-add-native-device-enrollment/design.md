# add-native-device-enrollment

## Decided

The journey is Papyrus, chosen 2026-10-31.

`device_enroll` loads or creates the device signer and returns the
classical public key and its fingerprint. It does not write the
account. The account row is `kind=identikey_auth` for that public
key on the signed-in XID. Consent is a signature by that key. That account binding is a
later node. Folding this decision does not deliver the route or a
native login, and the row is not surviving access until that login
exists. `revoke_device` stays unconditional. Account-facing removal
uses `revoke_account_access`, so the last counted login stays
without an explicit confirmation. Enrollment does not mint Elect. Hosted
signup still discards Elect. The hosted passkey path does not wait
on this row.

Papyrus selects the backend inside that journey: Secure Enclave on
macOS when the `enclave` feature is on, TPM on Linux when that
feature is on, TPM on Windows, otherwise a software key. The feature
flag is not evidence of which backend signed.

A standalone Linux enclave enrollment is not this journey.

## Open

None on this node. The account-binding route is a later node.
