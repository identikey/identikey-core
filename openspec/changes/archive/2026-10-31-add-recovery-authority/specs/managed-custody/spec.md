## ADDED Requirements

### Requirement: Recovery enrolls an ordinary passkey

An A1 recovery ceremony SHALL be allowed to enroll one credentials
row of kind `passkey`. That row SHALL be an ordinary A3 passkey.
`list_devices`, `revoke_device`, and C2 signing consent SHALL treat
it as a passkey enrolled at signup. The ceremony SHALL NOT store a
purpose-limited flag, a second passkey class, or an upgrade
assertion on that row.

The A1 proof and the recovery session SHALL NOT read
`managed_key_blob`, SHALL NOT decrypt it, SHALL NOT sign an
identikey-auth Challenge with it, and SHALL NOT grant Elect or
Transfer, including to a key that already exists. They SHALL NOT
mint an Elect key. After the passkey exists, those limits SHALL
still bind the recovery session. C2 signing consent SHALL be a
fresh assertion of that ordinary passkey, on the same terms as a
signup passkey.

#### Scenario: The mailbox enrolls a passkey and does not sign

- GIVEN an account with a verified A1 recovery ceremony and no passkey
- WHEN that ceremony enrolls a credential
- THEN the new row has kind `passkey`
- AND the ceremony does not decrypt `managed_key_blob` or produce an identikey-auth signature or an Elect key

#### Scenario: The enrolled passkey matches a signup passkey

- GIVEN a passkey enrolled by recovery and a passkey enrolled at signup
- WHEN both are listed and either is used for C2 signing consent
- THEN both appear as kind `passkey` with no purpose-limited flag
- AND consent accepts a fresh assertion of either passkey on the same terms

#### Scenario: Recovery does not sign before a passkey exists

- GIVEN an account whose only proof is the A1 recovery session
- WHEN the caller asks the server to sign an identikey-auth Challenge
- THEN the server does not sign
- AND `managed_key_blob` is unchanged

#### Scenario: The recovery session stays limited after enrollment

- GIVEN an ordinary passkey just enrolled by an A1 recovery session
- WHEN the caller presents that recovery session again and asks to read `managed_key_blob`, grant Elect, or grant Transfer
- THEN the server does not read the blob and does not grant Elect or Transfer
- AND a fresh assertion of the enrolled passkey still follows ordinary C2 consent
