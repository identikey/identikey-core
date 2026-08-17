# Tasks

- [ ] `list_devices` returns non-revoked credentials for a XID
- [ ] `revoke_device` sets `revoked_at`; list omits it
- [ ] No `device_trust` / `is_master` field on the list type
- [ ] Tests: insert → list → revoke → list empty of that id

Not owed here (bullets, not boxes):

- Token claims — `ccf`
- Refresh-token kill — `ccf`
- WebAuthn ceremony — `5gh.1`
