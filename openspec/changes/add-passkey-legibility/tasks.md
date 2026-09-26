# Tasks

- [ ] Registration persists `aaguid`, `backed_up`, and an optional nickname
- [ ] Pin the public AAGUID metadata list in the repo and resolve name and icon from it with no network call on `GET /account`
- [ ] `GET /account` lists each passkey: nickname, else provider name, else "Passkey"; icon only when the entry has one; backed-up; last used
- [ ] A missing entry or an unreadable list still renders the row and the rest of the page
- [ ] Assertion and authorization do not read `aaguid`
- [ ] Tests for a known AAGUID, an unknown AAGUID, a nickname override, and a ceremony that accepts two different AAGUIDs
