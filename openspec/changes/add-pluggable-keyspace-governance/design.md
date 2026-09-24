# Design: governed keyspaces as collective actors

## Status and boundaries

Proposed architecture, not current runtime behavior. The existing v1 contract remains
the compatibility baseline. New behavior requires a versioned upstream protocol;
older consumers cannot safely ignore governance fields and accept an admin alone.
No amended living spec or accepted ADR is implied by this draft.

## Three selectable mechanisms

Authorization answers who approved an exact transition. Settlement answers which
approved successor is effective. Secret release answers what cooperation is needed
to expose key material. Each descriptor pins a mechanism, version, configuration,
and verification semantics. A plugin is a recognized verifier, not arbitrary code
downloaded from an operation. Unknown or incompatible combinations fail closed.

Conceptual verifier input: prior accepted state, canonical proposed transition,
approval evidence, settlement evidence, and pinned verification context. Output:
accepted successor, pending evidence, conflict, or rejection. Network collection
and Lightning discovery sit outside deterministic verification. Policies bind the
keyspace ID, guild XID where established, previous state, policy version/hash,
sequence, action payload, and target state. Approvals count eligible distinct
principals under the outgoing policy, not merely signature count or device count.

Single-key and explicit-quorum authorization are initial candidates. FROST provides
a possible group signing key. Contract governance needs a specified evidence
verifier and a separate signing/custody route when the guild must emit signatures.
An EVM receipt does not by itself produce an Ed25519 signature.

## Version boundary (upstream proposal, not a core kind)

identikey-protocol owns the wire. This node does not add an op kind, field, or
`PublicKey.alg` in identikey-core. It states the contract a new upstream
governance profile must satisfy. Until that profile is in the protocol, core
keeps today's v1 verifier unchanged.

Consumers tell the versions apart from genesis, not from a side channel:

- A v1 genesis has no governance profile. Its log stays the seven protocol kinds.
  Admin is the roster boolean (`keyspace.rs` `require_admin`). Fade, outer/inner
  nest, and epoch-begin/commit keep their v1 meaning.
- A governance genesis commits a profile digest: authorization, settlement, and
  secret-release descriptors, each with a version and a declared maximum evidence
  size. The keyspace id is still that genesis content hash (ADR-012). The guild
  XID is not that id.

Migration of an existing v1 keyspace is one upstream transition authorized by the
current v1 admin set. It commits a profile and ends v1 administering validity at
that log position. It is not a local field on an old op. A v1 parser must reject
the post-cut administering bytes rather than accept them as a normal admin op.
A v1 replica that never fetches the cut stops at the prefix. Its later acceptance
of a v1-shaped admin op is stale. Governance-aware verifiers reject that op and
do not treat the stale replica as settlement.

After the cut, a pre-migration admin who is absent from the new policy cannot
append. Stripping governance evidence off a transition is a rejection, not a
fallback to the roster boolean. Outer and inner keyspaces migrate separately. A
governed parent does not govern a v1 child. Nesting across versions requires both
sides' current authorization and copies no policy. Fade and epoch changes on a
governed keyspace are governance transitions. On an unmigrated keyspace they stay
v1, including "concurrent epoch-begin is not merged."

## Collective identity and binding

The keyspace genesis hash identifies shared-key history. The XID derives from a
dedicated collective inception key and identifies the actor. Neither is an alias
for a founder XID, a PTK, or a mutable governance key fingerprint.

Canonical order, so neither id hashes the other:

1. The collective inception creates the XID first, from its own key, not the founder's.
2. Genesis, or a later binding transition, references that XID.
3. The binding proof covers both ids and is authorized by the keyspace's current
   governance and by the identity's current controllers. The proof is not an input
   to either id.

Until that proof verifies, clients do not treat the pair as an active guild actor.
One guild XID has one controlling keyspace. A second binding of the same XID is a
conflict and is rejected, not a silent replacement. A keyspace keeps its id across
migration and handoff.

Wallets, resolvers, and relying parties accept identity control only when all of
these match: the current identity document, the binding proof, and the keyspace
checkpoint that authorized that control. `authorize_elect` on a key in the previous
document is the personal-XID path. It is not collective control. A verifier that
does not implement the governance profile refuses control operations on a bound
collective XID. It does not fall open to the inception key. A verifier whose
checkpoint is older than the document's governance epoch refuses the same way.

Map of powers at that boundary:

- Sign and Auth are the collective signing mechanism named by the policy. They are
  not membership and not wrap decryption.
- Elect, Transfer, and Update of the guild document run only through the
  identity-control rule of the effective policy, against that same checkpoint.
- A delegation has explicit scope and expiry. It does not rewrite the guild
  document. It dies at handoff unless the incoming policy restates it.
- Member join and leave do not Elect the member's XID.

A retained inception or founder key remains historical evidence. After a handoff
that does not grant that key identity control, current-state verification rejects
its Elect, Transfer, Update, Sign, and Auth. Historical signatures stay valid as
history.

Agreement of a document, a binding, and a checkpoint is not freshness. An old
bundle still agrees with itself after a handoff. A new Sign, Auth, identity-control
operation, or secret release needs an admissible freshness witness. Naming a
witness type without the obligations below is not admissible, and the profile
cannot use it for those actions.

- `registry-head` has two different facts. A finalized checkpoint proves that
  this checkpoint was final. A current-head observation is a fresh read, at use
  time, that the pinned Registry's head is this checkpoint and that the read
  covers this action. Replaying the old finalized bytes is not that observation.
  The profile states the trusted Registry operators and the fault assumption
  (one operator, or independent consensus). It also states a maximum age for the
  observation. Past that age the observation is stale and the action is refused.
- `witness-set` is a quorum the predecessor policy named, with an explicit fault
  assumption (who may lie or go silent). The quorum stores the checkpoint it
  attests and refuses to attest a second sibling of the same predecessor.
  Attesting two siblings is equivocation: freeze, and no new release. Each
  attestation binds the action being authorized, so an old attestation does not
  authorize a later use. "No sibling I have stored" is not a claim that no
  withheld signature exists anywhere. A branch the quorum never recorded is not
  a final successor. A reader who has a current, non-equivocating quorum
  attestation of A may act on A. When a withheld branch appears later, it is not
  final unless the quorum records it. If the quorum had already recorded A and
  refuses the new branch, the new branch is rejected. If the quorum equivocated,
  both sides freeze.

`local-quorum` owner signatures alone are not this witness. They only show a
conflict after both branches have been seen. A profile with no admissible witness
cannot authorize new Sign, Auth, identity control, or secret release. Plaintext
already held stays usable.

The ordering point is a consume record, not a read and not a maximum age.
`registry-head` authorizes an action only when that action's consume entry is
in the finalized head before a later handoff entry. `witness-set` authorizes it
only when the quorum's durable log records that consume before it records a
later head. A read that is still inside its maximum age, and that nobody has
consumed, does not survive a handoff the consumer has not seen. A consume that
landed first stays authorized if the work finishes later. That finish is not a
new authorization. The same consume at a second consumer is a replay and fails.
If the witness cannot be reached between the read and the consume, there is no
consume and the action is unauthorized. A matching stale bundle, including an
old genuine attestation that was never consumed for this action, does not
authorize it. A restart drops cached reads and must consume again.

## Acting and controlling are different powers

Readers do not automatically become guild signers. The current policy separately
authorizes collective Sign/Auth use, operational delegation, and XID document
control (including Elect/Transfer/Update or equivalent supported privileges).
Biscuit remains the agency layer; possession of a guild credential alone does not
grant arbitrary rights at a relying service. Member join/leave does not Elect the
member's XID. Changes to the guild XID do require its identity-control authorization.

A policy certificate checked only inside core is not quorum control. The binding
rules above are the enforcement boundary every wallet, resolver, and relying party
uses. A policy-gated signer that holds a whole secret is operator custody. Threshold
cooperation is a different mechanism. The profile names which one it is. This node
does not pick a threshold library.

Operational agents receive explicit, bounded delegations. Policy specifies scope,
validity, revocation/freshness requirements, and whether delegation survives handoff.
No automatic survival is assumed in the baseline proposal.

## Handoff, recovery, and conflicts

The outgoing policy approves the entire replacement, including authority keys,
settlement and recovery settings. Incoming authority demonstrates usable control.
There is no transaction across the identity document, the key ceremony, and the
Registry. Each phase is its own evidence, and only the activation checkpoint
changes who governs.

- Prepare, authorized by the outgoing policy, names the successor policy, the
  identity and key changes, the settlement class, recovery settings, and which
  delegations die. Nothing external happens. Abort here is discard. The
  predecessor stays effective. A prepare bound to the wrong predecessor is rejected.
- Authorize, still the outgoing policy plus incoming usable-control evidence,
  binds those approvals to that exact prepare. Repeating it is idempotent.
  A different successor is a different transition. Exclusive control is not claimed.
- Effect steps are ordered and separate, and none of them makes the successor
  current. Parties may create an inactive successor key and prove possession.
  That is not a release of an existing secret and not current authority. The
  guild document may be staged. The collective-control verifier keeps the last
  activated document and checkpoint until the activation checkpoint. Existing
  shared secrets and the current whole control secret are not distributed before
  final settlement evidence and activation. Distributing one earlier is a
  violation: that power becomes unavailable, activation is refused, and abort
  records the disclosure without claiming it was recalled. If an outgoing holder
  knew the whole control secret, a possession proof of the replacement is
  required before activation. Without it, activation is refused. After a staged
  document or an inactive new key, with settlement still missing, the predecessor
  policy remains who may act. Abort discards the staged document and the unusable
  new key. Resume may continue only the same prepare. Successor control does not
  start early.
- Activate is one checkpoint naming the predecessor, the effect hashes, and the
  incoming policy. Missing evidence leaves the last activated checkpoint in force
  and the handoff pending. Who may act in that pending state is the policy of
  that last checkpoint, not the founder and not the half-finished successor.
- Resume may only supply the missing effects of the same prepare. The outgoing
  policy authorizes resume until activation. A resume that changes the successor
  is rejected.
- Abort is allowed only before activation, authorized by the outgoing policy or
  by a deadline that policy already set. Abort does not undeclare a key that an
  effect step already disclosed. That disclosure is recorded as irreversible, the
  disclosed key is retired, and the predecessor policy remains the governance
  authority. If the remaining control set is not safe, that power becomes
  unavailable. It is not handed back to the founder.

Owner replacement uses this same machine. A settlement-backend replacement does
too, with one extra rule: the migration transition itself is finalized by the
outgoing descriptor, never by the incoming one. Incoming readiness (the new pin
answers) may be required and is not finality. New-only finality does not adopt
a Registry. After activation, later transitions use the incoming descriptor.
Old-side and new-side blobs may sit in one migration only when each is labeled
`outgoing-finality` or `incoming-readiness` and both commit to that migration
hash. Any other mix of domains is still a reject. If required old-side evidence
is lost or reorged before activation, the migration returns to pending or aborts.
It does not activate. A recovery from that state exists only when the predecessor
policy already authorized it.

If an outgoing holder knew the complete signing/control secret, rotate relevant
keys before declaring exclusive control transferred. Verification against current
identity state rejects old authority; historical signatures remain historical proof.
Neither policy nor rotation retracts plaintext or old secret copies already exposed.

Recovery is optional and installed or changed under the effective policy before
the failure. A founder, host operator, or chain administrator gains no implicit
recovery power. Without a configured usable path, loss of quorum freezes governance.

For off-chain forks the result depends on settlement records, not on how many
approvals arrived. Zero records: stay at the predecessor, do not pick by arrival,
and do not start new identity or release actions on either approval. One record:
that successor is effective and the other approval is rejected. Two records:
freeze at the predecessor. A recovery or resolution mechanism cannot be installed
by one disputed branch to authorize that branch. Ordinary use of previously held
secrets is not revoked by a freeze. An approval-only profile never makes a
successor effective.

Settlement is `registry-head` or `witness-set`. `local-quorum` owner signatures
are approval certificates, not a third settlement class. The rules below describe
those certificates and the Registry receipt. They do not override the one-record
rule above.

- `local-quorum` is final as an authorization certificate when the predecessor
  policy's distinct-principal signatures verify over the exact transition.
  Incomplete signatures are provisional. That certificate is not an admissible
  freshness witness. A new secret, Sign, Auth, or identity-control action still
  needs the witness rules above. Without that witness the action is unavailable
  even though the certificate is final.
- `registry` is provisional on inclusion or a receipt that does not meet the
  pinned finality rule. It is final only on evidence that meets that rule
  (the descriptor names the rule: a confirmation depth or a finalized checkpoint).
  A reorg that drops an unreleased checkpoint returns the transition to pending.
  A reorg after release does not recall the secret. It freezes further release.

Four layers stay distinct. Approval is the policy signatures. Settlement is
which approved successor is effective. Activation is the checkpoint that changes
who governs. Freshness is the consume record for a new action under the already
effective checkpoint. A freshness witness is not a second, quieter settlement
rule. When the profile's settlement is the witness set or the Registry head,
that record is the predecessor-authorized ordering. Owner signatures alone are
approval. They are not the effective successor.

One settlement record selects its successor. A fully signed sibling that the
witness refuses is rejected, and the recorded successor does not freeze. Freeze
is two settlement records: the quorum attested both siblings, or two finalized
Registry heads name different successors. Arrival order does not choose. A later
checkpoint is not a tie-break unless the predecessor policy already named that
procedure. While a sibling is withheld, the recorded successor stays effective.
Learning the withheld approval later does not freeze it if settlement still
refuses it. A late second settlement record after a release leaves that
plaintext released and freezes further release. A replica that lacks the
settlement record stays pending. It does not adopt the other approval.

## Community Registry

Pin the deployment domain using genesis/checkpoint, chain ID, contract identity,
verifier version, and relevant code/upgrade authority commitments. Discovery names
and endpoints are transport metadata. Moving machines need not change authority;
changing the chain or governing contract does.

A Registry adapter validates approved state transitions and canonical succession,
not merely transaction inclusion or a recorded hash. Finality, reorg, and rollback
are the `registry` class above. The profile states whether ordering is one operator
or independent consensus participants. Neither is described as the other.

Adapter input is the predecessor hash, the canonical transition, approval evidence,
settlement evidence, release evidence, and the pinned context (mechanism ids and
versions, policy hash, Registry pin). Output is accept, pending, conflict, or
reject, with the evidence that failed. Every blob must commit to the same
transition hash and the same pin. A mix of domains is a reject. Evidence over the
descriptor's declared maximum is a reject, not a truncation. A profile with no
maximum is rejected at genesis. A combination is admissible only when each
mechanism's declared compatible-with set names the others. An unknown combination
fails closed. There is no fallback to single-admin.

Same-address code that the pinned upgrade authority does not cover is an
unauthorized upgrade and is rejected. An authorized upgrade is a governance
transition under the outgoing policy, not a discovery update. Moving to a new
chain or contract is a settlement-descriptor handoff, the same phase machine as
any other handoff.

Registry-dependent governance remains pending during unavailable settlement; it
does not downgrade to local admin approval. Existing committed offline access can
continue subject to its own data-access policy.

## Delivery and unresolved choices

This node delivers the architecture contract above: version cut, binding
evidence, handoff phases, finality classes, and the adapter predicates. Those
are an upstream proposal for identikey-protocol, not core kinds and not a
library choice. Runtime, threshold suites, chain consensus, and concrete recovery
schemes stay downstream. A fresh architecture read has to accept this text
before any of that is dispatched. The 2026-09-24 send-back (R1–R5) is the input
this section closes.
