# Tasks

- [ ] Registration and assertion options include hints `hybrid`, `security-key`, and `client-device`
- [ ] Options still omit `authenticatorAttachment` and still require a discoverable credential on registration
- [ ] Options never send a hint list that is only `client-device`
- [ ] No new route and no server-rendered QR
- [ ] Test the emitted options JSON for those hints and the absent attachment
