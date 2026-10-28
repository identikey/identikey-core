# Tasks

- [ ] Registration and assertion options include hints `client-device`, `hybrid`, `security-key`, in that order
- [ ] Options still omit `authenticatorAttachment` and still require a discoverable credential on registration
- [ ] The hint list is absent or exactly those three values; a one-value or two-value list is not sent
- [ ] No new route and no server-rendered QR
- [ ] Tests assert the exact hint list and order, and the absent attachment, on registration, discoverable assertion (`ceremonies.rs:225`, `:250`), and allow-list assertion (`:219`, `:345`) options
- [ ] Fresh advise after preparation

## Owed (advise 2026-10-27, opus-arch-review — send-back)

- [x] Hint order does not lead with `hybrid`: use `client-device`, `hybrid`, `security-key`, or record a dated manual check that a `hybrid`-first list still shows the local/synced passkey on Chrome desktop's first screen; update design.md and the delta scenario to match
- [x] Delta invariant reworded: the hint list is empty or contains all three values (no single- or two-value list), for creation and request options, in place of "only `client-device`"
- [ ] Tests assert the exact hint list and order on registration, discoverable assertion (`ceremonies.rs:225`, `:250`), and allow-list assertion (`:219`, `:345`) options
- [x] Record a manual hybrid ceremony (phone OS, desktop browser + version) in the change, or state "not verified on hardware"
- [x] Name a browser/case where hybrid is absent today without hints, or restate the Why as a sheet-order nudge
