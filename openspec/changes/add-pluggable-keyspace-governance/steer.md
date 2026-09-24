# steer add-pluggable-keyspace-governance

**When.** 2026-09-24
**Depth.** standard

## Decided

- Selectable, replaceable governance; single-admin bootstrap is valid (user).
- Initial governance assignment can be the first signed action (user).
- A community can operate its own Registry over Lightning's service mesh (user).
- Full handoff: no residual founder privilege except roles explicitly granted by
  the incoming policy (user).
- Optional predeclared recovery; no implicit operator override (user).
- Conflicting approved off-chain changes freeze disputed governance at the last
  agreed state until the configured resolution procedure succeeds (user).
- A guild/group keyspace needs its own XID so it can act as an agent (user).

## Skipped / still open

- Exact wire version and binding representation; no local protocol fork.
- XID control verifier and custody model for each governance mechanism.
- Concrete conflict-resolution and recovery procedures and their liveness limits.
- Registry consensus/finality evidence and EVM verification approach.
- Threshold signing/decryption implementation choices.

## Feeds change

Preserve stable collective identity through governance changes. Separate members'
XIDs from the guild XID and separate governance approval from possession of the
guild signing key. Make mechanism selection explicit, with no implicit fallback.
Prepare the common contract first; leave backend implementations provisional.
These decisions authorize drafting, not deployment or runtime implementation.
