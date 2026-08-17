## ADDED Requirements

### Requirement: Devices are listable, revocable credentials

The system SHALL treat a `credentials` row as the device record. It
SHALL list non-revoked credentials for a XID and SHALL revoke a
credential by setting `revoked_at`. A revoked credential SHALL NOT
appear in a subsequent list. The list type SHALL NOT include
`device_trust`, `is_master`, or a master/temporary enum.

#### Scenario: Register then list

- GIVEN a stored account
- WHEN a passkey credential is inserted and `list_devices` is called
- THEN the list contains that credential id and not a trust claim

#### Scenario: Revoke hides the device

- GIVEN a listed credential C
- WHEN `revoke_device` is called for C and `list_devices` is called
  again
- THEN C is absent from the list
