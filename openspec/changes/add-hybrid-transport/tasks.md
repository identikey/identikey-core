# Tasks

- [ ] Registration and assertion options include hints `hybrid`, `security-key`, and `client-device`
- [ ] Options still omit `authenticatorAttachment` and still require a discoverable credential on registration
- [ ] Options never send a hint list that is only `client-device`
- [ ] No new route and no server-rendered QR
- [ ] Test the emitted options JSON for those hints and the absent attachment

## Owed (advise 2026-10-27, opus-arch-review — send-back)

- [ ] Hint order does not lead with `hybrid`: use `client-device`, `hybrid`, `security-key`, or record a dated manual check that a `hybrid`-first list still shows the local/synced passkey on Chrome desktop's first screen; update design.md and the delta scenario to match
- [ ] Delta invariant reworded: the hint list is empty or contains all three values (no single- or two-value list), for creation and request options, in place of "only `client-device`"
- [ ] Tests assert the exact hint list and order on registration, discoverable assertion (`ceremonies.rs:225`, `:250`), and allow-list assertion (`:219`, `:345`) options
- [ ] Record a manual hybrid ceremony (phone OS, desktop browser + version) in the change, or state "not verified on hardware"
- [ ] Name a browser/case where hybrid is absent today without hints, or restate the Why as a sheet-order nudge
