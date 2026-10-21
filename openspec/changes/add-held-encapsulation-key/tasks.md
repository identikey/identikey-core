# Tasks

- [x] Fresh advise after preparation — accepted by `reviews/2026-10-21-advise-3.md` (opus-arch-review); contract sha256 proposal `0cc4a2daf4db`, design `1bd64c678b8f`, managed-custody delta `89501661b4c3`, guild-keyspaces delta `e978e22a96cd`, tasks `a8fc312a8c34`, on `main` @ `ff9efe6`
- [x] Add `encapsulation_key_blob` and the C2-only, legacy-nullable check. C0, C1, C3, and C4 stay null.
- [x] Seal the user X25519 at signup in an `IKEK` v1 envelope bound to the XID and `c2_wrap_recipient`. Do not seal the operational companion X25519 or the Elect private. Do not write the scalar into `managed_key_blob`.
- [x] Unwrap a keyspace §7 `x25519-xchacha20poly1305` data key in a new store connection whose inputs do not include the user `PrivateKeyBase`.
- [x] Refuse unwrap and export when the only credential is an account cookie. Accept a single-use encapsulation consent (A3 live path; A4 only from a held Elect key). The managed Sign key is not A4. A managed-challenge consent does not open the seal.
- [x] `POST /account/encapsulation/begin` and `POST /account/encapsulation/export` only. Export returns the 32-byte scalar, unpadded base64url, `Cache-Control: no-store`, outside `spa_cors`, with no HTML. No HTTP body returns a data key.
- [x] Library unwrap takes the A3 or A4 proof and, in one transaction, verifies it, marks the row used, checks the wrap digest, unwraps, and audits. No live caller in this change. Reject a small-order ephemeral and an all-zero DH output. An Elect rewrite that changes the wrap recipient nulls the seal.
- [x] On success, write consent-log `encapsulation_export` or `encapsulation_unwrap` and a custody event in the same transaction as the key use.
- [x] Climb refuses while a seal is present and no `encapsulation_export` entry exists. After a logged export, climb nulls the column and does not return the scalar.
- [x] Existing C2 rows with a null seal fail closed. Swapped account, swapped recipient, and `IKMK` presented as `IKEK` fail closed.
- [x] Amend ADR-012 item 4's live-instance paragraph, including that IdentiKey can open a PTK wrapped to a held C2 member. Update the `c2_native` and `OperationalEd25519::generate` comments.
- [x] Regenerate `.sqlx` against `identikey-core-sqlx` and keep `identikey-core-test` off `sqlx migrate`.

## Owed from advise 2026-10-21 (opus-arch-review, send-back)

- [x] B1: Pin the seal-open consent: begin step, domain-tagged transcript with purpose (`export` / `unwrap`) distinct from `identikey-managed-consent-v1\n`, single use, expiry, account binding; add a scenario where a responder/session-bind consent is refused at export.
- [x] B2: Decide hosted unwrap: library-only in this change (data key never leaves the process), or name the route, its recipient, and its B1 binding. Make proposal, delta, and design agree.
- [x] B3: Add a MODIFIED `guild-keyspaces` delta replacing "unwrap SHALL fail until that private is user-held" and the inert scenario; state in it and in the ADR-012 amendment that IdentiKey can open PTKs wrapped to a held C2 member.
- [x] B4: Require a consent-log entry and custody event on successful export/unwrap, with a scenario.
- [x] N1–N6 recorded in the contract (AAD domain tag, ephemeral small-order + all-zero DH, export CORS exemption + no-store, export-before-climb, A4 unreachable, policy-not-crypto). N7 is the comment task above.
- [x] Fresh advise after B1–B4 — accepted by `reviews/2026-10-21-advise-3.md` (opus-arch-review); contract sha256 proposal `0cc4a2daf4db`, design `1bd64c678b8f`, managed-custody delta `89501661b4c3`, guild-keyspaces delta `e978e22a96cd`, tasks `a8fc312a8c34`, on `main` @ `ff9efe6`

## Owed from advise 2 2026-10-21 (opus-arch-review, send-back)

- [x] B1: Give `unwrap` consent a defined finish. Library unwrap takes the A3 assertion or A4 signature and, in one transaction, verifies it against the stored row, rechecks expiry/purpose/unused, marks used, opens, unwraps, and audits. No finished-but-unconsumed row. State that this change has no live unwrap caller and name the first one.
- [x] B2: Bind `unwrap` consent to the wrap. Begin stores the Wrap digest, the transcript carries it, unwrap refuses a different wrap before decrypt, and the consent log records it. Add the scenario "consent for W does not open W′".
- [x] N-c: Pin the encapsulation-consent transcript byte encoding (field widths or length prefixes, attempt id form, u64 BE times, hash) and one fixed digest vector, with a scenario.
- [x] N-d: Export and unwrap recheck the credential row and the custody row under the same `FOR UPDATE` locks `revoke_device` and climb take, right before decrypt. Add a "Revocation wins" scenario for export.
- [x] N-a: State what an Elect rewrite of the user X25519 does to the seal (open fails closed; null it or leave it).
- [x] N-b: Test that a registered SPA origin gets no `Access-Control-Allow-Origin` on begin or export.
- [x] Fresh advise after advise-2 owed boxes — accepted by `reviews/2026-10-21-advise-3.md` (opus-arch-review); contract sha256 proposal `0cc4a2daf4db`, design `1bd64c678b8f`, managed-custody delta `89501661b4c3`, guild-keyspaces delta `e978e22a96cd`, tasks `a8fc312a8c34`, on `main` @ `ff9efe6`
