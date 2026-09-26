# steer add-passkey-legibility

**When.** 2026-09-26
**Depth.** standard

## Decided

- Provider label: maintained public AAGUID metadata list, including icons (user). Unknown, missing, or unloadable metadata shows Passkey. AAGUID is never a policy input.
  Why: the account page should name the authenticator people actually used, not a four-name guess.
- Row label: stored nickname, else provider name, else Passkey (user). Also backed-up and last used.
  Why: the nickname is the person's own name for the row; the provider is the fallback.

## Skipped

- (none)

## Feeds change

Activated in chat 2026-09-26 for this bead only. Pin the public list in the repo so the account page does not fetch it per view. Do not gate ceremonies on AAGUID.
