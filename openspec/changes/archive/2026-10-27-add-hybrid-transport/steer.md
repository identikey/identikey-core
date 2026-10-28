# steer add-hybrid-transport

**When.** 2026-09-26
**Depth.** standard

## Decided

- Build the standard hybrid/caBLE transport into the hosted ceremonies (user). The browser shows its own QR.
  Why: a phone-to-computer passkey should be the platform flow. A second QR protocol would fork WebAuthn.
- Do not build a bespoke QR protocol (already the bead; confirmed).

## Skipped

- (none)

## Feeds change

Activated in chat 2026-09-26 for this bead only. Add the `hybrid` hint beside the other hints. Do not set `authenticatorAttachment`. Do not implement caBLE in this server.
