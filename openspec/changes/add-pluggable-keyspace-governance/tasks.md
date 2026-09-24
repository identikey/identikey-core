# Tasks

- [x] Capture user steering and collective-XID requirement in the proposal.
- [x] Draft governance requirements, boundary design, and adversarial scenarios.
- [x] Reconcile the upstream versioned wire and the existing guild-keyspaces admin,
  genesis, fade, nesting, and epoch requirements; specify old-client rejection.
- [x] Define canonical XID/keyspace binding and collective identity-control evidence,
  including verification by wallets, resolvers, and relying parties.
- [x] Define complete handoff activation/resume/abort behavior across keyspace state,
  guild XID updates, key custody, delegates, and settlement.
- [x] Define conflict-resolution/finality and predeclared-recovery contracts, including
  offline freshness and irreversible key-release limits.
- [x] Specify adapter compatibility, evidence bounds, and Registry identity/upgrade trust.
- [ ] Obtain independent architecture review of the revised contract.
- [x] Record the accepted architecture as an amendment/successor to ADR-012, with
  explicit upstream references and downstream implementation acceptance packets.

## Owed by architecture review — 2026-09-24

See `reviews/2026-09-24-advise.md`; these refine the open contract tasks above.

- [x] R1: Specify upstream version/migration rejection and legacy-client limits;
  cover stripped evidence, old-admin continuation, nesting, fade, and epochs.
- [x] R2: Specify canonical binding and collective-control verification across
  wallets/resolvers/relying parties; cover retained keys, stale state, and double binding.
- [x] R3: Specify handoff preparation/activation/resume/abort and authority at each
  boundary; cover interrupted effects, retries, delegates, and settlement migration.
- [x] R4: Specify provisional/final evidence, release/freshness limits, and ordering
  of recovery versus handoff; cover late forks, partitions, and finality contradictions.
- [x] R5: Specify adapter compatibility predicates, evidence bounds, and Registry
  upgrade/migration authorization; cover mixed evidence and same-address code changes.
- [ ] Obtain fresh independent architecture acceptance after R1-R5 are reconciled.
- [x] Fresh advise after preparation

## Downstream handoffs (not implementation owed by this change)

- nod-governance-runtime: common verifier, single-key and explicit-quorum adapters.
- nod-collective-identity: dedicated guild XID, binding, signing/authentication,
  identity-control updates and bounded agency; depends on upstream contract and verifier.
- nod-holder-key-lifecycle: usable key possession and wrap/rotate behavior.
- nod-threshold-signing / nod-threshold-release: evaluate and implement selected schemes.
- nod-registry-settlement / nod-community-registry: finality adapter and local deployment.
- nod-replica-repair: revalidate historical findings against the now-archived runtime.

## Owed by fresh architecture review — 2026-09-24

See `reviews/2026-09-24-re-advise.md`; fresh acceptance remains open.

- [x] R6: Define current-authority freshness and rollback assumptions for identity
  control, Sign/Auth, and secret release; reconcile stale-reader guarantees with
  late-fork limits and cover matching stale bundles, restart, and partitioned releasers.
- [x] R7: Reconcile pre-activation document/key effects with the finality release
  gate; define staged/current state and permitted powers after each interruption,
  abort, or resume, including Registry settlement missing after key distribution.
- [x] R8: Pin migration finality to explicit outgoing/incoming settlement roles and
  bind authorized old/new evidence domains; cover old-only and new-only finality,
  successful activation, and loss/reorg of required old-side evidence.

## Owed by second fresh architecture review — 2026-09-24

See `reviews/2026-09-24-re-advise-2.md`; fresh acceptance remains open.

- [x] R9: Define admissible freshness-witness trust, replay/rollback, and action
  ordering guarantees; reconcile partition refusal with hidden signed siblings.
  Cover a replayed complete witness bundle, a live witness unaware of a withheld
  sibling, and handoff concurrent with an outstanding action witness.

## Owed by third fresh architecture review — 2026-09-24

See `reviews/2026-09-24-re-advise-3.md`; fresh acceptance remains open.

- [x] R10: Define the common ordering boundary for action use and handoff under
  both freshness-witness types; reconcile maximum-age observations with immediate
  invalidation. Cover delayed first use after handoff, completion after an earlier
  action commitment, replay at multiple consumers, and partition after observation.
- [x] R11: Reconcile approved-fork freeze and local-quorum finality with witness
  recording/rejection; distinguish approval, settlement, activation, and freshness.
  Cover a withheld then revealed fully signed sibling, witness refusal versus
  equivocation, and recovery racing handoff under the same admitted profile.

## Owed by fourth fresh architecture review — 2026-09-24

See `reviews/2026-09-24-re-advise-4.md`; fresh acceptance remains open.

- [x] R12: Reconcile the earlier approval-fork freeze requirement and delivery-order
  scenario with settlement-record selection; clarify admitted settlement classes
  and any approval-only profile. Cover zero, one, and two settlement records with
  both approval delivery orders, including recovery versus handoff, with consistent
  outcomes across the design and delta.
