# add-pluggable-keyspace-governance

> **ACTIVE BUILD**

**Rigor:** architecture, with instrument-level acceptance for downstream runtime work.
**Capability:** keyspace-governance (ADDED).
**Intention:** nod-pluggable-guild-governance / nod-governance-contract.

## Why

A shared keyspace currently grants administering power to each admin actor. Communities
need selectable governance, signed transfers of authority, and a collective identity that
can act as an agent. A guild needs its own stable XID as well as its existing keyspace ID.
The founder may bootstrap alone and later hand control to owners, a threshold signer,
or a contract on the community's own Registry. These changes must preserve identity
without leaving an implicit founder or operator override.

## What

- Define a versioned governance contract separating authorization, settlement/finality,
  and secret release, with an explicit compatibility contract between mechanisms.
- Define signed bootstrap and outgoing-policy-authorized handoff, optional predeclared
  recovery, and conflict freeze at the last agreed state.
- Bind the guild's own XID to its keyspace history; distinguish reader membership,
  collective signing/authentication, identity-control powers, and delegated agency.
- Define Registry instance identity separately from Lightning service discovery.
- Specify adversarial acceptance cases and upstream protocol work before runtime dispatch.

## Impact

- Capabilities: ADDED `keyspace-governance` as a proposed contract; existing
  `guild-keyspaces` v1 behavior remains unchanged by this draft.
- ADRs: propose an amendment/successor to docs/ARCHITECTURE.md ADR-012 when accepted.
- Protocol owner: identikey-protocol. Its keyspace wire and single-actor log verifier
  need coordinated design; this core proposal does not mint local op kinds or fields.
- Consumers: identikey-core, holder wallets, Recrypt adapters, Lightning service mesh,
  and community Registry deployments. No new Cargo dependency is proposed here.

## User journey & surfaces

No new UI because this change prepares the protocol and core verification contract;
holder signing clients and later Lightning Admin are the intended consuming surfaces.

A founder creates a guild with a dedicated XID and an explicit initial policy, then
signs a handoff to the community's chosen mechanism. Authorized agents authenticate
as the guild and act within explicit delegations. A valid handoff preserves both IDs
and retires outgoing authority. Missing approvals or settlement evidence leave the
transition pending. Conflicting approved off-chain transitions freeze disputed
governance. A community may run its selected Registry on a local mini-PC reached
through Lightning without making service discovery an authority source.

## Preparation — 2026-09-24

Outcome: revised for the user's collective-XID requirement. Source: conversation
steering and notes on identikey-core-trr (closed historical epic; not reopened).
At core HEAD 669d4f9, add-keyspace-runtime and add-access-node-wrap are archived;
the old review's repair findings require revalidation, not automatic reactivation.
Anchors: openspec/specs/guild-keyspaces/spec.md; docs/ARCHITECTURE.md ADR-001,
ADR-010 through ADR-012; crates/identikey-keys/src/{keyspace,xid,privilege}.rs;
docs/LEARNINGS.md on C2 key possession and X25519 roster constraints.

The new contract is not covered by the archived architecture acceptances. User
instruction `change` authorizes this draft; no runtime/deployment campaign has been
requested. Upstream wire, XID control enforcement, and finality proofs remain design
inputs to resolve before implementation. The referenced living-specs capability is
absent in this checkout; openspec/AGENTS.md supplies the local layout/fold rules.

## Preparation — 2026-09-24 send-back

Outcome: revised. Authority: the 2026-09-24 `activate` of this node, which covers
resolving the contract tasks and obtaining review, not runtime. Input: Astra
send-back `reviews/2026-09-24-advise.md` (READER astra-arch-review) at HEAD after
`36759ce`. R1–R5 are now in `design.md` and
`specs/keyspace-governance/spec.md`. No living spec and no ADR-012 amendment yet.
Fresh advise is owed. The prior send-back does not accept this text.
R6–R8 from `reviews/2026-09-24-re-advise.md` are now in the same design and
delta: freshness witnesses, staged pre-activation effects, and outgoing-descriptor
finality for Registry migration. That re-advise does not accept this later text. R9 from
`reviews/2026-09-24-re-advise-2.md` is now in the same design and delta:
witness replay, fault assumptions, and no refusal duty for a sibling the
quorum never recorded. That review does not accept this later text. R10–R11
from `reviews/2026-09-24-re-advise-3.md` are now in the same files: consume
is the ordering point, and one settlement record selects a successor while
two settlement records freeze. That review does not accept this later text.

## Activation — 2026-09-24

User instruction `activate` explicitly activates this architecture node. Preparation
outcome: the drafted scope and recorded steering remain valid. Authority covers
resolving the contract tasks, obtaining independent architecture review, and recording
the accepted decision. The unresolved design inputs above remain owed work; activation
does not claim they are resolved or that review has accepted the contract. Downstream
runtime, cryptographic backend implementations, and deployments remain out of scope.

## Out of scope

- Runtime repairs — nod-replica-repair, first revalidate against current code.
- Governance runtime — nod-governance-runtime, after this contract and upstream wire.
- User-held key lifecycle — nod-holder-key-lifecycle; no operator-key workaround.
- FROST implementation — nod-threshold-signing; no library or DKG selected yet.
- Threshold PRE/decryption — nod-threshold-release; no new cryptographic construction here.
- Registry deployment or blockchain launch — nod-registry-settlement and nod-community-registry.
- Collective identity runtime — nod-collective-identity, dependent on this contract,
  upstream XID enforcement, and an operative governance verifier.
- New OIDC claims, UI implementation, or replacing Biscuit/Recrypt with guild membership.
