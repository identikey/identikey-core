# design add-client-sector-pin

Security-relevant: a wrong sector re-mints every pairwise `sub` at an RP.
Amended 2026-09-29 after send-back R1/R2 (`reviews/2026-09-29-advise.md`).

## Shape

`ClientJson` gains `sector: Option<String>`; the primary client reads
`IDENTIKEY_CLIENT_SECTOR`. Both surfaces go through `client_from_spec`,
which now takes the sector and:

- pairwise (subject type omitted, empty, or `pairwise`) with the sector
  missing or empty → error naming the client id;
- public → sector optional; when absent the client id fills
  `Client::new`'s argument (never read by `sub`).

**Pins are opaque and verbatim.** The configured string is passed to the
KDF byte-for-byte: no trimming, lowercasing, IDNA, or URL parsing. Empty is
missing. Salt, XID encoding, subject-type defaults, and the KDF are
unchanged; sector selection is the only seam that moves.

**Runtime never derives.** `client_from_spec` and everything on the boot and
request path take the sector only from configuration. The single permitted
derivation is `legacy_sector` in the preflight module below, used only to
compare.

## Legacy semantics (reproduced exactly by `legacy_sector`)

1. `merge_redirects(redirect, redirects)`: singular `redirect` first if
   non-empty, then `redirects` in order, skipping empty and duplicate
   entries.
2. Take the first merged entry. `url::Url::parse(..)`, then `host_str()`.
3. Parse failure or no host → the literal `default`.

This is today's `sector_from_redirect(merge_redirects(..)[0])`, moved, not
rewritten.

## Preflight: `identikey-server check-clients`

A subcommand using the same parsing path as boot (`optional_client`,
`extra_clients`). It reads only the client configuration
(`IDENTIKEY_CLIENT_*`, `IDENTIKEY_CLIENTS`), builds every client with the
candidate loader, and prints one row per client: id, source
(primary | json), subject type, pinned sector, legacy sector, `match`. It
never prints secrets. Exit non-zero if the candidate loader refuses the
configuration, or if any pairwise client's pin differs from its legacy
value. It needs no salt, network, or database.

## Rollout (human-gated; abort leaves the old service running)

0. **Baseline.** Before any mutation, sign in once each to taskmaster and
   Conduit with a known XID and record the pairwise `sub` each RP shows.
   Record the sha256 of `IDENTIKEY_PAIRWISE_SALT` in escrow and in the
   running process.
1. **Inventory.** For every client-config key (`IDENTIKEY_CLIENTS`,
   `IDENTIKEY_CLIENT_ID/_REDIRECT/_AUTH_METHOD/_SUBJECT_TYPE`), compare the
   sha256 of host escrow, guest `/run/mjolnir/secrets.env`, and the running
   process (`/proc/<pid>/environ`). Any mismatch → stop and reconcile first.
2. **Propose pins.** Write `sector` for every effective pairwise JSON
   client and `IDENTIKEY_CLIENT_SECTOR` for a pairwise primary, each set to
   `legacy_sector`. Keep a timestamped escrow backup.
3. **Preflight.** Run the candidate `check-clients` against the proposed
   configuration, streamed from escrow into the process environment (never
   written to disk). Every pairwise row must say `match`; the loader must
   accept everything. Failure → restore the backup; nothing has changed
   for users.
4. **Stage.** Write the proposed values into the guest env and restart the
   *old* binary (it ignores the new keys). Confirm login works. This only
   proves the old binary still boots; step 3 is the proof for the new one.
5. **Cut over.** Deploy the new binary. Re-check the salt hash, then repeat
   the step-0 sign-ins: both `sub` values must equal the baseline.
   Sector byte equality (step 3) plus an unchanged salt covers every
   client, so two live probes are enough.
6. **Rollback.** New binary refuses to boot or a `sub` differs → redeploy
   the previous commit. The old binary ignores `sector`, so the pinned
   escrow is safe to leave in place.

## Boundaries

- An operator later editing a non-empty pin still changes identities. This
  node makes redirects independent of the pin; guarding the pin itself is
  `identikey-core-2zj.3` (owner-signed records).
- A misconfigured client stops the whole provider at boot. Accepted: an
  implicit fallback is the identity hazard this change removes. Step 3
  catches it before users see it.

## Why not keep deriving with a warning

A warning is read after the identities already moved. Refusing to boot is
loud at the only moment the operator is watching.
