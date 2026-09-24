# keyspace-governance

Living truth for pluggable keyspace governance. Folded from
`add-pluggable-keyspace-governance` (2026-09-24). ADR-013 records the
decision. This does not change the v1 guild-keyspaces wire.

These requirements apply to an explicitly versioned governance-capable
keyspace protocol. They do not alter the accepted v1 wire.

### Requirement: Explicit selectable governance

A governance-capable keyspace SHALL declare versioned authorization, settlement,
and secret-release mechanisms with their configuration and compatibility rules.
Verifiers SHALL reject unsupported mechanisms rather than fall back to single-admin
authorization. A signed bootstrap SHALL establish the initial policy, which MAY
be single-admin. No implicit superadmin SHALL exist outside that policy.

#### Scenario: Founder bootstrap
- GIVEN a new keyspace with a founder-selected single-key policy
- WHEN valid bootstrap evidence is verified
- THEN that explicit policy governs subsequent transitions.

#### Scenario: Unsupported governance
- GIVEN a consumer that cannot verify the selected mechanism
- WHEN it receives an administering operation
- THEN it refuses to accept the transition even if an actor signature is valid.

### Requirement: Exact transition authorization

Approvals SHALL bind the protocol domain, keyspace, prior accepted state, effective
policy, sequence, proposed action and resulting state, and established guild XID.
Quorum evaluation SHALL count distinct eligible principals under the prior policy.
Duplicate operations SHALL be idempotent; stale-state approvals SHALL NOT authorize
a different successor. Membership SHALL NOT itself confer governing authority.

#### Scenario: Repeated signer
- GIVEN a three-owner approval requirement
- WHEN one owner's approval is repeated or supplied through multiple device keys
- THEN it does not satisfy three distinct-owner approvals.

#### Scenario: Substituted transition
- GIVEN approvals for one policy and predecessor
- WHEN an attacker changes the recipient, action, guild, or predecessor
- THEN verification rejects the substituted transition.

### Requirement: Full governance handoff

A replacement policy SHALL be authorized by the effective outgoing policy, with
required incoming-control evidence. A handoff SHALL declare its activation boundary
and required identity/key changes. After activation, outgoing founder powers SHALL
end except roles explicitly granted by the incoming policy. Retained full private
keys SHALL be retired through verifiable key rotation where exclusive control changes.

#### Scenario: Founder becomes an ordinary member
- GIVEN a founder who previously governed alone
- WHEN a completed handoff installs quorum governance without a founder override
- THEN the founder cannot administer or control the guild identity alone.

#### Scenario: Partial handoff
- GIVEN a handoff whose required identity rotation or finality evidence is missing
- WHEN its approvals are collected
- THEN the system reports it pending rather than claiming exclusive control transferred.

### Requirement: Optional predeclared recovery

A guild MAY configure a separate recovery policy. Installing or changing it SHALL
require current governance authorization. Recovery SHALL use the previously effective
policy and SHALL NOT grant implicit founder, service-operator, or Registry-operator
authority. Without a usable authorized recovery path, loss of authority SHALL leave
governance unavailable.

#### Scenario: Host attempts emergency takeover
- GIVEN lost governing keys and no policy granting the host recovery authority
- WHEN the host proposes replacement owners
- THEN the transition is rejected.

### Requirement: Conflict and settlement semantics

Approval of two successors SHALL NOT by itself freeze an already settled
successor, and SHALL NOT make either successor effective. With zero settlement
records, governance SHALL stay at the predecessor, new identity and secret-release
actions SHALL NOT treat either approval as effective, and replicas SHALL NOT
pick by arrival order. With one settlement record, that successor SHALL be
effective and the other approval SHALL be rejected, in either delivery order.
With two settlement records, governance SHALL freeze at the predecessor.
Unavailable settlement SHALL NOT cause an authorization downgrade. An
approval-only profile SHALL NOT make a successor effective.

#### Scenario: Delivery order differs
- GIVEN two approved successors and no settlement record
- WHEN replicas observe the approvals in opposite orders
- THEN both stay at the predecessor and neither approval becomes effective

#### Scenario: One settlement record, either order
- GIVEN approvals A and B and one settlement record for A
- WHEN one replica sees B first and another sees A first
- THEN both treat A as effective and reject B

#### Scenario: Registry is offline
- GIVEN governance requiring Registry finality
- WHEN settlement evidence cannot be obtained
- THEN the transition remains pending without reverting to founder authorization.

### Requirement: Stable collective XID

A governance-capable guild SHALL have a dedicated XID, distinct from member XIDs
and from its keyspace genesis identifier, with a verifiable binding between the two.
Binding activation SHALL require authorization of both the keyspace and the identity.
Membership changes, key rotation and governance handoff SHALL preserve the guild XID
and keyspace ID. The binding construction SHALL avoid circular hash dependencies.

#### Scenario: Existing guild gains agency
- GIVEN an existing keyspace and a dedicated collective XID
- WHEN their currently authorized controllers approve and complete the binding
- THEN relying parties can verify which collective identity represents the keyspace.

#### Scenario: Owner and key replacement
- GIVEN a bound guild undergoing an authorized governance and key transition
- WHEN the transition completes
- THEN its XID and keyspace ID remain unchanged while current authority changes.

### Requirement: Governed collective action and identity control

Guild signing, authentication, delegation and identity-document control SHALL be
authorized according to the effective policy and enforced by the declared signing
and identity-verification mechanisms. Reading a shared secret SHALL NOT grant these
powers. Membership SHALL NOT grant agency capabilities or modify a member XID.
The mechanism SHALL disclose whether enforcement relies on an operator holding a
whole secret or on cryptographic threshold cooperation. Delegations SHALL have
explicit scope, validity, revocation rules and handoff treatment.

#### Scenario: Reader impersonates guild
- GIVEN a member who can decrypt but lacks collective signing authority
- WHEN the member attempts to authenticate or delegate as the guild
- THEN the attempt fails despite valid membership.

#### Scenario: Removed controller uses an old key
- GIVEN a completed handoff retiring a former controller's guild key
- WHEN that controller signs a new identity rewrite or guild action
- THEN current-state verification rejects it without invalidating historical signatures.

### Requirement: Registry authority is independent of discovery

A selected Registry SHALL have pinned chain and contract identity, verification
rules, finality assumptions and applicable upgrade authority. Service discovery
SHALL NOT replace those trust anchors. A deployment SHALL state whether its ordering
authority is a single operator or independent consensus participants.

#### Scenario: Discovery redirects to another chain
- GIVEN a guild pinned to its community Registry
- WHEN Lightning discovers an endpoint serving a different chain or contract
- THEN its governance evidence is rejected even if the endpoint name matches.

#### Scenario: Registry host moves
- GIVEN unchanged Registry authority and verifiable state continuity
- WHEN its endpoint moves to another local machine
- THEN discovery updates do not constitute a governance handoff.

### Requirement: Version cut rejects legacy administering

A governance-capable keyspace SHALL be recognized by a genesis governance profile.
A v1 keyspace SHALL remain on v1 admin, fade, nest, and epoch rules until one
upstream migration transition, authorized by its current v1 admin set, commits a
profile. identikey-core SHALL NOT mint a local op kind or field for that cut.
After the cut, governance-aware verifiers SHALL reject v1-shaped administering
operations, including those a stale v1 replica still accepts. A v1 parser SHALL
reject post-cut administering bytes rather than treat them as a current admin
operation. Stripped governance evidence SHALL be a rejection, not a fallback to
roster-admin. Outer and inner keyspaces SHALL migrate independently. Cross-version
nesting SHALL require both sides' current authorization and SHALL NOT copy policy.

#### Scenario: Old admin continues after the cut

- GIVEN a keyspace whose migration cut has committed
- WHEN a pre-migration admin submits a v1-shaped administering operation
- THEN governance-aware verifiers reject it even if a v1 replica accepts it

#### Scenario: Stripped governance evidence

- GIVEN a transition that requires governance evidence
- WHEN that evidence is removed and only an actor signature remains
- THEN verifiers reject the transition and do not apply roster-admin rules

#### Scenario: Client never learns the migration

- GIVEN a v1 replica that has not fetched the migration cut
- WHEN it is asked to treat a post-cut operation as v1 admin authority
- THEN it does not gain a new administering path, and governance-aware consumers do not adopt its acceptance as settlement

#### Scenario: Governed nesting

- GIVEN a governed keyspace and a v1 keyspace
- WHEN one is nested under the other without both sides' current authorization
- THEN the nest is rejected and neither policy replaces the other

### Requirement: Collective control evidence

Wallets, resolvers, and relying parties SHALL accept guild identity control only
when the current identity document, the binding proof, and the authorizing
keyspace checkpoint agree. A verifier that does not implement the governance
profile SHALL refuse control operations on a bound collective XID. A verifier
whose checkpoint is older than the document's governance epoch SHALL refuse them.
One guild XID SHALL bind to at most one controlling keyspace. Sign, Auth, Elect,
Transfer, and Update of the guild document SHALL follow the effective policy at
that checkpoint. Membership and wrap decryption SHALL NOT grant those powers.
Member XIDs SHALL stay unchanged by guild operations.

#### Scenario: Retained founder key

- GIVEN a completed handoff that does not grant the founder identity control
- WHEN the founder key signs an Elect, Transfer, Update, Sign, or Auth on the guild
- THEN current-state verification rejects it and historical signatures stay historical

#### Scenario: Stale document

- GIVEN a document that was valid under an older checkpoint
- WHEN a verifier whose checkpoint is older than the document's governance epoch is asked to apply it
- THEN the verifier refuses the control operation

#### Scenario: Double binding

- GIVEN a guild XID already bound to one keyspace
- WHEN a second keyspace presents a binding for that same XID
- THEN verifiers reject the second binding and do not replace the first silently

### Requirement: Handoff phases are independently abortable

A handoff SHALL proceed only through prepare, authorize, effect, and activate.
Only the activation checkpoint SHALL make the incoming policy effective. Missing
effect evidence SHALL leave the last activated policy in force. Resume SHALL only
complete the same prepare. Abort SHALL be allowed only before activation, SHALL
NOT undeclare a disclosed key, and SHALL NOT restore founder authority. If the
remaining control set is unsafe after a disclosed key, that power SHALL become
unavailable. Owner replacement and settlement-backend replacement SHALL use this
same machine. No phase SHALL assume one transaction across identity, keys, and settlement.

#### Scenario: Rotation disclosed, settlement missing

- GIVEN a handoff whose key-rotation effect has already disclosed a secret
- WHEN settlement evidence is missing
- THEN the handoff stays pending under the last activated policy, the disclosed key stays retired, and abort does not claim the secret was unexposed

#### Scenario: Resume changes the successor

- GIVEN an authorized prepare for one successor
- WHEN a resume names a different successor
- THEN verification rejects the resume

#### Scenario: Abort before activation

- GIVEN a prepared handoff that has not activated
- WHEN the outgoing policy aborts it
- THEN the predecessor policy remains the authority and no exclusive control is claimed

### Requirement: Finality gates secret release

Approval signatures SHALL NOT by themselves be settlement. `local-quorum`
signatures SHALL be the approval certificate. When the profile settles by
`registry-head` or `witness-set`, exactly one settlement record SHALL select the
effective successor, and another approved sibling that settlement refuses SHALL
be rejected without freezing the recorded one. Two settlement records for
different successors of one predecessor SHALL freeze at that predecessor.
Arrival order SHALL NOT choose. A new secret SHALL be released only after
settlement and a consume record for that same action. A late second settlement
record after a release SHALL leave released plaintext released and SHALL freeze
further release. A replica without the settlement record SHALL stay pending and
SHALL NOT adopt a different approval.

#### Scenario: Late fork after release

- GIVEN a secret already released under one final successor
- WHEN a conflicting final successor of the same predecessor appears
- THEN the released plaintext stays released and further secret release stops

#### Scenario: Recovery races a handoff

- GIVEN one predecessor, a fully approved handoff, and a fully approved recovery
- WHEN settlement has recorded exactly one of them
- THEN that one is effective, the other is rejected, and replicas that see the approvals in either order agree once they have that same settlement record

#### Scenario: Withheld sibling is revealed

- GIVEN settlement has recorded successor A and a secret was released for A
- WHEN a fully approved sibling B is revealed and settlement refuses to record B
- THEN A stays effective, B is rejected, and the released plaintext stays released

#### Scenario: Settlement equivocates

- GIVEN a quorum or Registry head that records two different successors of one predecessor
- WHEN a replica sees those two settlement records in either order
- THEN it freezes at the predecessor and releases nothing further

#### Scenario: Contradictory finalized checkpoints

- GIVEN two finalized Registry checkpoints naming different successors of one predecessor
- WHEN a later checkpoint builds on only one of them
- THEN verifiers still freeze unless the predecessor policy already named that later checkpoint as the resolution procedure

### Requirement: Adapter evidence is one transition

An adapter SHALL take the predecessor, the canonical transition, approval,
settlement, and release evidence, and the pinned context, and SHALL return
accept, pending, conflict, or reject. Every evidence blob SHALL commit to that
same transition and pin. Evidence from another transition or domain SHALL be
rejected. Evidence beyond the descriptor's stated maximum SHALL be rejected and
SHALL NOT be truncated. A profile that states no maximum, or names a mechanism
combination outside the declared compatible-with sets, SHALL be rejected at
genesis. Same-address code outside the pinned upgrade authority SHALL be an
unauthorized upgrade. An authorized upgrade or a move to a new chain or contract
SHALL be a governance transition under the outgoing policy, not a discovery update.

#### Scenario: Mixed evidence

- GIVEN approval evidence for one transition
- WHEN it is presented with settlement evidence for another
- THEN the adapter rejects the composition

#### Scenario: Oversized evidence

- GIVEN a descriptor whose maximum evidence size is stated
- WHEN a blob exceeds that size
- THEN the adapter rejects it and does not truncate it into acceptance

#### Scenario: Unauthorized same-address upgrade

- GIVEN a Registry pin whose upgrade authority does not cover a code change
- WHEN that code changes at the same address
- THEN governance evidence under the new code is rejected

#### Scenario: Registry migration

- GIVEN a guild pinned to one chain and contract
- WHEN operators move it to another chain without an outgoing-policy handoff of the settlement descriptor
- THEN verifiers reject the new Registry as authority

### Requirement: Freshness witness for new authority

A document, binding, and checkpoint that agree with each other SHALL NOT by
themselves authorize a new Sign, Auth, identity-control operation, or secret
release. The profile SHALL name an admissible freshness witness, either
`registry-head` or `witness-set`, meeting the trust, replay, and ordering rules
in the design. A profile that only names the witness, or that has only
`local-quorum` signatures, SHALL NOT authorize those new actions. Previously
held plaintext SHALL remain usable. A finalized checkpoint or an old attestation
SHALL NOT by itself prove the head is still current. A witness-set attestation
SHALL bind the action. A witness set SHALL persist the checkpoint it attests and
SHALL NOT attest a second sibling of the same predecessor. Equivocation SHALL
freeze new release. A branch the quorum has not recorded SHALL NOT be a final
successor, and a reader with a current non-equivocating attestation of one
recorded successor SHALL NOT be required to refuse it because a withheld
signature exists elsewhere. An outstanding witness SHALL become void once the
head or quorum record moves, and replaying it SHALL fail.

#### Scenario: Stale bundle still agrees

- GIVEN a handoff that has activated and a founder key that was current before it
- WHEN a verifier is shown the pre-handoff document, binding, and checkpoint, which still agree
- THEN the founder cannot Sign, authenticate, control the guild document, or release a secret

#### Scenario: Restart from an old snapshot

- GIVEN a verifier restored from a snapshot older than the latest checkpoint
- WHEN its freshness witness is unavailable
- THEN it performs no new Sign, Auth, identity control, or secret release, and it may still use plaintext it already held

#### Scenario: Replayed witness bundle

- GIVEN a genuine pre-handoff attestation that matches the pre-handoff checkpoint
- WHEN that whole bundle is presented after the handoff as authority for a new action
- THEN the action is refused

#### Scenario: Witness has not seen a withheld sibling

- GIVEN a non-equivocating quorum that has recorded successor A and has never been shown sibling B
- WHEN a reader with that current attestation of A is asked to release a secret for A
- THEN the reader may release for A, and B is not final until the quorum records it

#### Scenario: Handoff beats an outstanding action

- GIVEN a read or attestation for an action that was never consumed
- WHEN handoff activation is already in the head
- THEN the first use of that action is refused even if the read is inside its maximum age

#### Scenario: Consume landed first

- GIVEN an action whose consume record is in the head before the handoff entry
- WHEN the work finishes after the handoff is known
- THEN that action stays authorized and a second consumer replaying it is refused

#### Scenario: Partition before consume

- GIVEN a verifier that read the head and then lost the witness
- WHEN it cannot record a consume
- THEN the action is unauthorized and plaintext already held stays usable

### Requirement: Pre-activation effects are not current

Before activation, a handoff MAY stage a successor document and MAY distribute
an inactive successor key with a possession proof. It SHALL NOT distribute an
existing shared secret or the current whole control secret before final
settlement evidence and activation. The collective-control verifier SHALL keep
using the last activated document and checkpoint. A staged document SHALL NOT
become current because it was published. Abort before activation SHALL discard
the staged document and the inactive key, SHALL leave the predecessor policy in
force, and SHALL NOT grant successor control. If an existing secret was
distributed early, that power SHALL become unavailable, activation SHALL be
refused, and abort SHALL record the disclosure without recalling it.

#### Scenario: Registry settlement missing after a staged document

- GIVEN a Registry-backed handoff whose successor document is staged and whose finality evidence is missing
- WHEN a verifier is asked who may act
- THEN the last activated policy is current and the staged document grants no control

#### Scenario: New key distributed before finality

- GIVEN an inactive successor key that was distributed with a possession proof
- WHEN Registry finality has not arrived
- THEN the new key cannot Sign, authenticate, or control the guild, and no existing secret has been released

#### Scenario: Abort after those effects

- GIVEN either of those pending states
- WHEN the outgoing policy aborts
- THEN the staged document and inactive key are discarded, the predecessor policy remains, and successor control has not started

### Requirement: Migration finality is the outgoing descriptor

The transition that replaces a settlement descriptor SHALL be finalized only by
the outgoing descriptor. Incoming readiness evidence SHALL NOT be that finality.
After activation, later transitions SHALL use the incoming descriptor. Old-side
and new-side evidence SHALL be accepted in one migration only when each blob is
labeled `outgoing-finality` or `incoming-readiness` and both commit to the same
migration. Any other mixed domain SHALL be rejected. New-only finality SHALL NOT
activate the migration. Loss or reorg of required old-side evidence before
activation SHALL return the migration to pending or abort it. An exceptional
recovery SHALL be valid only when the predecessor policy already authorized it.

#### Scenario: Old-only finality

- GIVEN outgoing finality for a migration and no incoming readiness evidence
- WHEN the profile requires that readiness
- THEN the migration stays pending and does not activate

#### Scenario: New-only finality

- GIVEN finality evidence only from the incoming Registry
- WHEN the outgoing descriptor has not finalized the migration
- THEN verifiers reject activation

#### Scenario: Completed migration

- GIVEN outgoing finality, labeled incoming readiness, and an activation checkpoint for the same migration
- WHEN a later transition is proposed
- THEN it is settled under the incoming descriptor

#### Scenario: Old-side evidence reorgs before activation

- GIVEN a migration that is not yet activated
- WHEN the required old-side finality evidence is reorged away
- THEN the migration does not activate, and recovery is possible only along a path the predecessor policy already named
