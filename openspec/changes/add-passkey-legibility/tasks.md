# Tasks

- [x] Registration persists `aaguid`, `backed_up`, and an optional nickname
- [x] Pin the public AAGUID metadata list in the repo and resolve name and icon from it with no network call on `GET /account`
- [x] `GET /account` lists each passkey: nickname, else provider name, else "Passkey"; icon only when the entry has one; backed-up; last used
- [x] A missing entry or an unreadable list still renders the row and the rest of the page
- [x] Assertion and authorization do not read `aaguid`
- [x] Tests for a known AAGUID, an unknown AAGUID, and a nickname override
- [ ] An assertion test runs two valid credentials with different stored presentation AAGUIDs; the ceremony result does not depend on the AAGUID. The store insert at `store.rs` is not that test
- [ ] A missing or legacy backup value renders as unknown, not as "Not backed up". The registration BS bit stays the snapshot and is not rewritten on assertion
- [ ] Fresh advise after preparation

Evidence (2026-09-29): `passkey_metadata` tests (known/unknown/malformed
list, unsafe icon), `ceremonies` registration-metadata tests, the store test
for two AAGUIDs on one account (persistence and lookup only; it does not
assert), and the `pages` tests (nickname over provider, fallback, escaping).
The nickname is accepted by `register/finish`; no page offers a field for it yet.
Browser: local signup shows the row (`Passkey · Not backed up · Never used`),
and after sign-in `Last used <date>`. That browser line predates the unknown
backup wording. Not yet folded.

## Owed from advise — 2026-10-27, astra-arch-review

Review: [2026-10-27-advise.md](reviews/2026-10-27-advise.md).

- [x] Reconcile nickname precedence with missing/unreadable metadata fallback in the design and delta: preserve any trimmed nonempty nickname; qualify generic fallback scenarios; cover nickname plus unavailable metadata and blank nicknames.
- [ ] Define backup display semantics (registration snapshot versus maintained status, BS versus backup eligibility, and missing/legacy metadata); make display expectations and focused verification match, without presenting unknown state as an observed negative. The contract text now says registration BS snapshot and unknown for a missing value. The page still maps NULL to false and renders "Not backed up", so this box stays open until that display and a focused check match.
- [x] Resolve the checked ceremony-test evidence gap: verify real assertions for two valid credentials with different stored presentation AAGUIDs, or explicitly reconcile the promised verification; do not claim store-only lookup tests execute the assertion scenario.
