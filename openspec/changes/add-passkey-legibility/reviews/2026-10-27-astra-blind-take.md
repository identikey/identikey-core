1. Pin AAGUID, backup state, nickname, and provider metadata as presentation only; none may influence ceremony acceptance or authorization.
2. Pin extraction to the same registration response after webauthn-rs verifies it; malformed presentation metadata must not reject an otherwise valid registration.
3. Pin backup state to the BS bit, distinguish it from backup eligibility, and state whether the displayed value is a registration snapshot or a maintained status.
4. Pin deterministic label precedence: trimmed nonempty nickname, resolved provider name, then “Passkey”; provider lookup failure must preserve a usable nickname.
5. Pin the public metadata source and vendored revision, with offline resolution and graceful fallback for unknown AAGUIDs or malformed data.
6. Refuse remote or active icon URLs and raw metadata HTML; escape labels and render accepted embedded icons only as inert images.
7. Preserve account-session isolation, account-scoped non-revoked rows, signed-out behavior, and the prohibition on exposing key material or creating accounts implicitly.
8. Specify legacy/null metadata, empty lists, and absent last-use behavior without requiring retroactive identification or an unrequested rename-management surface.
9. Reconcile the proposal’s “columns dropped/count only” claims with cited code that already stores metadata and renders rows; the living spec has no naming requirement to modify.
10. Accept the tradeoff that a small pinned provider list becomes stale and cannot uniquely identify a device, in exchange for deterministic, private, authentication-independent display hints.
