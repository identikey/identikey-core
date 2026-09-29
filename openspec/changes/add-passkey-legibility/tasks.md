# Tasks

- [x] Registration persists `aaguid`, `backed_up`, and an optional nickname
- [x] Pin the public AAGUID metadata list in the repo and resolve name and icon from it with no network call on `GET /account`
- [x] `GET /account` lists each passkey: nickname, else provider name, else "Passkey"; icon only when the entry has one; backed-up; last used
- [x] A missing entry or an unreadable list still renders the row and the rest of the page
- [x] Assertion and authorization do not read `aaguid`
- [x] Tests for a known AAGUID, an unknown AAGUID, a nickname override, and a ceremony that accepts two different AAGUIDs

Evidence (2026-09-29): `passkey_metadata` tests (known/unknown/malformed
list, unsafe icon), `ceremonies` registration-metadata tests, the store test
for two AAGUIDs on one account (ceremony rows still keyed by credential id),
and the `pages` tests (nickname over provider, fallback, escaping). The
nickname is accepted by `register/finish`; no page offers a field for it yet.
Browser: local signup shows the row (`Passkey · Not backed up · Never used`),
and after sign-in `Last used <date>`. Not yet folded.
