# Design — threshold read, fail-closed (ADR-007 §3–4)

Security-sensitive comparison. No new network dependency.

## Surface

```text
resolve_documents(tier, docs) -> Result<WinningDoc, ResolveError>
```

- `docs` is an ordered list of `{ source: Uri, bytes: &[u8] }`.
- Parse failure on one source drops that source (it is not a vote).
  Zero valid documents is `ResolveError::NoDocument`.
- Two valid documents whose provenance marks are not on the same
  chain → `ResolveError::Duplicity`. Do not pick by timestamp, source
  order, or "ours."
- Same chain → the highest mark wins.
- A document with no provenance mark is comparable only to other
  unmarked copies of the *same bytes*. Two different unmarked
  documents are duplicity (no chain to reconcile them).

Use `bc-xid` provenance as the ordering primitive. Do not invent a
second "newer" clock.

## Tiers

- `ResolutionTier::Cached` — caller may pass a single previously
  fetched document. Ordinary OIDC login.
- `ResolutionTier::Consequential` — key-graph change, delegation,
  custody migration, wallet-class. The function refuses
  `Cached`-tagged input and refuses N<2 when the caller claims C3+.

N and K are caller policy (ADR-007: C1/C2 default N=1; C3+ N≥2, K=2).
The library exposes the comparison; it does not fetch.

## What this is not

- Not an HTTP client. Fetch is a later node once
  `add-xid-resolver` exists as one of N.
- Not a store write. Comparison only.
