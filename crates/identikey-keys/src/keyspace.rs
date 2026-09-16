//! Replica of identikey-keyspace-v1 ops on identikey-log (ADR-012).
//!
//! Postgres, if used, is a cache of [`ReplicaSnapshot`]. The log is home.
//! C2 rows of this store are §7 wrap recipients until identikey-protocol
//! `ikp-2l8` adds `PublicKey.alg` `x25519`. Do not mint that alg here.

use std::collections::{HashMap, HashSet};

use dcbor::prelude::*;
use identikey_log::{Hash32, Op, codec};

const KIND_JOIN: &str = "keyspace.join";
const KIND_CHANGE: &str = "keyspace.change";
const KIND_LEAVE: &str = "keyspace.leave";
const KIND_ASSIGN: &str = "keyspace.assign-node";
const KIND_NEST: &str = "keyspace.nest";
const KIND_BEGIN: &str = "keyspace.epoch-begin";
const KIND_COMMIT: &str = "keyspace.epoch-commit";

const ALG_ED25519: &str = "ed25519";
const ALG_P256: &str = "p256";

/// In-memory replica. Optional Postgres materialization stores [`ReplicaSnapshot`].
#[derive(Debug, Clone, Default)]
pub struct KeyspaceReplica {
    spaces: HashMap<Hash32, KeyspaceState>,
    /// Ops we have seen, for ancestry.
    seen: HashMap<Hash32, SeenOp>,
    identikey_sign: Option<Hash32>,
}

#[derive(Debug, Clone)]
struct SeenOp {
    parents: Vec<Hash32>,
}

#[derive(Debug, Clone)]
struct KeyspaceState {
    id: Hash32,
    profile: String,
    epoch: u64,
    roster: Vec<RosterEntry>,
    wraps: Vec<Wrap>,
    blacklist: Vec<Vec<u8>>,
    node: Option<[u8; 32]>,
    faded: bool,
    pending_begins: Vec<PendingBegin>,
}

#[derive(Debug, Clone)]
struct PendingBegin {
    hash: Hash32,
    parents: Vec<Hash32>,
    epoch: u64,
    wraps: Vec<Wrap>,
    conflicted: bool,
}

#[derive(Debug, Clone)]
struct RosterEntry {
    admin: bool,
    actor: Option<Hash32>,
    #[allow(dead_code)]
    puks: Vec<PublicKey>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PublicKey {
    alg: String,
    key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Wrap {
    alg: String,
    recipient: Vec<u8>,
    epoch: u64,
}

/// Snapshot for an optional Postgres cache. Not the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSnapshot {
    pub keyspace: Hash32,
    pub epoch: u64,
    pub profile: String,
    pub faded: bool,
    pub roster: Vec<CachedRosterEntry>,
    pub wraps: Vec<CachedWrap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRosterEntry {
    pub admin: bool,
    pub actor: Option<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedWrap {
    pub alg: String,
    pub recipient: Vec<u8>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    #[error("unknown kind")]
    UnknownKind,
    #[error("missing or invalid body")]
    BadBody,
    #[error("identikey Sign cannot author a keyspace op")]
    SignActor,
    #[error("identikey Sign cannot be a wrap recipient")]
    SignRecipient,
    #[error("actor is not admin on the applied roster")]
    NotAdmin,
    #[error("genesis actor must appear admin:true in the same join body")]
    GenesisAdmin,
    #[error("keyspace faded")]
    Faded,
    #[error("unknown keyspace")]
    UnknownKeyspace,
    #[error("epoch conflict")]
    EpochConflict,
    #[error("native x25519 PublicKey.alg is not minted here (ikp-2l8)")]
    X25519RosterAlg,
    #[error("ChangeBody must not carry wraps")]
    ChangeWraps,
    #[error("identikey-log: {0}")]
    Log(String),
}

impl KeyspaceReplica {
    pub fn new() -> Self {
        Self::default()
    }

    /// IdentiKey C2 Sign public. Refused as `Op.actor` and wrap recipient.
    pub fn refuse_sign(&mut self, pk: Hash32) {
        self.identikey_sign = Some(pk);
    }

    pub fn get(&self, id: &Hash32) -> Option<ReplicaSnapshot> {
        self.spaces.get(id).map(|s| ReplicaSnapshot {
            keyspace: s.id,
            epoch: s.epoch,
            profile: s.profile.clone(),
            faded: s.faded,
            roster: s
                .roster
                .iter()
                .map(|e| CachedRosterEntry {
                    admin: e.admin,
                    actor: e.actor,
                })
                .collect(),
            wraps: s
                .wraps
                .iter()
                .map(|w| CachedWrap {
                    alg: w.alg.clone(),
                    recipient: w.recipient.clone(),
                    epoch: w.epoch,
                })
                .collect(),
        })
    }

    pub fn wraps(&self, id: &Hash32) -> Option<Vec<(String, Vec<u8>, u64)>> {
        self.spaces.get(id).map(|s| {
            s.wraps
                .iter()
                .map(|w| (w.alg.clone(), w.recipient.clone(), w.epoch))
                .collect()
        })
    }

    pub fn pending_begin_count(&self, id: &Hash32) -> usize {
        self.spaces
            .get(id)
            .map(|s| s.pending_begins.iter().filter(|b| !b.conflicted).count())
            .unwrap_or(0)
    }

    pub fn apply(&mut self, op: &Op) -> Result<Hash32, ApplyError> {
        let hash = codec::content_hash(op).map_err(|e| ApplyError::Log(e.to_string()))?;
        if let Some(sign) = self.identikey_sign {
            if op.actor == sign {
                return Err(ApplyError::SignActor);
            }
        }
        match op.kind.as_str() {
            KIND_JOIN => self.apply_join(op, hash)?,
            KIND_CHANGE => self.apply_change(op, hash)?,
            KIND_LEAVE => self.apply_leave(op, hash)?,
            KIND_ASSIGN => self.apply_assign(op, hash)?,
            KIND_NEST => self.apply_nest(op, hash)?,
            KIND_BEGIN => self.apply_begin(op, hash)?,
            KIND_COMMIT => self.apply_commit(op, hash)?,
            _ => return Err(ApplyError::UnknownKind),
        }
        self.seen.insert(
            hash,
            SeenOp {
                parents: op.parent_hashes.clone(),
            },
        );
        Ok(hash)
    }

    fn apply_join(&mut self, op: &Op, hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let keyspace = opt_hash(&body, "keyspace")?;
        let roster = roster_list(&body)?;
        let wraps = wrap_list(&body, self.identikey_sign)?;
        if wraps_contain_sign(&wraps, self.identikey_sign) {
            return Err(ApplyError::SignRecipient);
        }
        let epoch = uint_field(&body, "epoch").unwrap_or(0);
        let profile = text_field(&body, "profile").unwrap_or_else(|| "house".to_owned());
        match keyspace {
            None => {
                // Outer genesis.
                if !roster.iter().any(|e| e.admin && e.actor == Some(op.actor)) {
                    return Err(ApplyError::GenesisAdmin);
                }
                self.spaces.insert(
                    hash,
                    KeyspaceState {
                        id: hash,
                        profile,
                        epoch,
                        roster,
                        wraps,
                        blacklist: Vec::new(),
                        node: None,
                        faded: false,
                        pending_begins: Vec::new(),
                    },
                );
            }
            Some(id) => {
                self.require_admin(&id, op.actor)?;
                let space = self
                    .spaces
                    .get_mut(&id)
                    .ok_or(ApplyError::UnknownKeyspace)?;
                merge_roster(&mut space.roster, roster);
                if space.profile != "access-node" {
                    space.wraps = wraps;
                    space.epoch = epoch;
                }
            }
        }
        Ok(())
    }

    fn apply_change(&mut self, op: &Op, _hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        if get_cbor(&body, "wraps").is_some() {
            return Err(ApplyError::ChangeWraps);
        }
        let id = req_hash(&body, "keyspace")?;
        self.require_admin(&id, op.actor)?;
        let space = self
            .spaces
            .get_mut(&id)
            .ok_or(ApplyError::UnknownKeyspace)?;
        if let Ok(roster) = roster_list(&body) {
            merge_roster(&mut space.roster, roster);
        }
        if let Some(CBORCase::Array(items)) = get_cbor(&body, "blacklist").map(CBOR::into_case) {
            for item in items {
                if let Ok(b) = bytes_cbor(&item) {
                    space.blacklist.push(b);
                }
            }
        }
        if let Some(p) = text_field(&body, "profile") {
            space.profile = p;
        }
        Ok(())
    }

    fn apply_leave(&mut self, op: &Op, _hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let id = req_hash(&body, "keyspace")?;
        self.require_admin(&id, op.actor)?;
        let leaving = opt_hash(&body, "actor")?;
        let space = self
            .spaces
            .get_mut(&id)
            .ok_or(ApplyError::UnknownKeyspace)?;
        if let Some(actor) = leaving {
            space.roster.retain(|e| e.actor != Some(actor));
        }
        if let Some(CBORCase::ByteString(b)) = get_cbor(&body, "recipient").map(CBOR::into_case) {
            let rec = b.to_vec();
            space.wraps.retain(|w| w.recipient != rec);
        }
        space.faded = !space.roster.iter().any(|e| e.admin);
        Ok(())
    }

    fn apply_assign(&mut self, op: &Op, _hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let id = req_hash(&body, "keyspace")?;
        self.require_admin(&id, op.actor)?;
        let node = req_bytes32(&body, "node")?;
        let space = self
            .spaces
            .get_mut(&id)
            .ok_or(ApplyError::UnknownKeyspace)?;
        space.node = Some(node);
        Ok(())
    }

    fn apply_nest(&mut self, op: &Op, hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let outer = req_hash(&body, "outer")?;
        self.require_admin(&outer, op.actor)?;
        let roster = roster_list(&body)?;
        let wraps = wrap_list(&body, self.identikey_sign)?;
        let profile = text_field(&body, "profile").unwrap_or_else(|| "access-node".to_owned());
        let epoch = uint_field(&body, "epoch").unwrap_or(0);
        self.spaces.insert(
            hash,
            KeyspaceState {
                id: hash,
                profile,
                epoch,
                roster,
                wraps,
                blacklist: Vec::new(),
                node: None,
                faded: false,
                pending_begins: Vec::new(),
            },
        );
        Ok(())
    }

    fn apply_begin(&mut self, op: &Op, hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let id = req_hash(&body, "keyspace")?;
        self.require_admin(&id, op.actor)?;
        let epoch = uint_field(&body, "epoch").ok_or(ApplyError::BadBody)?;
        let wraps = wrap_list(&body, self.identikey_sign)?;
        let parents = op.parent_hashes.clone();
        let existing: Vec<(Hash32, Vec<Hash32>, bool)> = self
            .spaces
            .get(&id)
            .ok_or(ApplyError::UnknownKeyspace)?
            .pending_begins
            .iter()
            .map(|b| (b.hash, b.parents.clone(), b.conflicted))
            .collect();
        let mut newly_conflicted: HashSet<Hash32> = HashSet::new();
        let mut this_conflicted = false;
        for (ph, pp, already) in &existing {
            if *already {
                continue;
            }
            if !is_ancestor(&self.seen, *ph, hash, &parents)
                && !is_ancestor(&self.seen, hash, *ph, pp)
            {
                newly_conflicted.insert(*ph);
                this_conflicted = true;
            }
        }
        let parents_exactly_one = existing
            .iter()
            .filter(|(h, _, _)| parents.contains(h))
            .count()
            == 1;
        if parents_exactly_one {
            this_conflicted = false;
        }
        let space = self
            .spaces
            .get_mut(&id)
            .ok_or(ApplyError::UnknownKeyspace)?;
        if parents_exactly_one {
            for pending in &mut space.pending_begins {
                pending.conflicted = !parents.contains(&pending.hash);
            }
        } else {
            for pending in &mut space.pending_begins {
                if newly_conflicted.contains(&pending.hash) {
                    pending.conflicted = true;
                }
            }
        }
        space.pending_begins.push(PendingBegin {
            hash,
            parents,
            epoch,
            wraps,
            conflicted: this_conflicted,
        });
        Ok(())
    }

    fn apply_commit(&mut self, op: &Op, _hash: Hash32) -> Result<(), ApplyError> {
        let body = map_body(op)?;
        let id = req_hash(&body, "keyspace")?;
        self.require_admin(&id, op.actor)?;
        let epoch = uint_field(&body, "epoch").ok_or(ApplyError::BadBody)?;
        let space = self
            .spaces
            .get_mut(&id)
            .ok_or(ApplyError::UnknownKeyspace)?;
        let live: Vec<(Hash32, Vec<Wrap>)> = space
            .pending_begins
            .iter()
            .filter(|b| !b.conflicted && b.epoch == epoch)
            .map(|b| (b.hash, b.wraps.clone()))
            .collect();
        let Some((begin_hash, wraps)) = live.first() else {
            return Err(ApplyError::EpochConflict);
        };
        if live.len() != 1 {
            return Err(ApplyError::EpochConflict);
        }
        if !op.parent_hashes.contains(begin_hash) {
            return Err(ApplyError::EpochConflict);
        }
        space.wraps.clone_from(wraps);
        space.epoch = epoch;
        space.pending_begins.clear();
        Ok(())
    }

    fn require_admin(&self, id: &Hash32, actor: Hash32) -> Result<(), ApplyError> {
        let space = self.spaces.get(id).ok_or(ApplyError::UnknownKeyspace)?;
        if space.faded {
            return Err(ApplyError::Faded);
        }
        let ok = space
            .roster
            .iter()
            .any(|e| e.admin && e.actor == Some(actor));
        if ok {
            Ok(())
        } else {
            Err(ApplyError::NotAdmin)
        }
    }
}

fn is_ancestor(
    seen: &HashMap<Hash32, SeenOp>,
    ancestor: Hash32,
    _node: Hash32,
    parents: &[Hash32],
) -> bool {
    let mut stack: Vec<Hash32> = parents.to_vec();
    let mut visited: HashSet<Hash32> = HashSet::new();
    while let Some(p) = stack.pop() {
        if p == ancestor {
            return true;
        }
        if !visited.insert(p) {
            continue;
        }
        if let Some(s) = seen.get(&p) {
            stack.extend(s.parents.iter().copied());
        }
    }
    false
}

fn map_body(op: &Op) -> Result<Map, ApplyError> {
    let bytes = op.body.as_ref().ok_or(ApplyError::BadBody)?;
    let cbor = CBOR::try_from_data(bytes).map_err(|_| ApplyError::BadBody)?;
    match cbor.into_case() {
        CBORCase::Map(map) => Ok(map),
        _ => Err(ApplyError::BadBody),
    }
}

fn get_cbor(map: &Map, key: &str) -> Option<CBOR> {
    map.get::<&str, CBOR>(key)
}

fn opt_hash(map: &Map, key: &str) -> Result<Option<Hash32>, ApplyError> {
    let Some(v) = get_cbor(map, key) else {
        return Ok(None);
    };
    Ok(Some(hash32_cbor(&v)?))
}

fn req_hash(map: &Map, key: &str) -> Result<Hash32, ApplyError> {
    opt_hash(map, key)?.ok_or(ApplyError::BadBody)
}

fn req_bytes32(map: &Map, key: &str) -> Result<[u8; 32], ApplyError> {
    req_hash(map, key)
}

fn text_field(map: &Map, key: &str) -> Option<String> {
    get_cbor(map, key).and_then(|v| match v.into_case() {
        CBORCase::Text(s) => Some(s),
        _ => None,
    })
}

fn uint_field(map: &Map, key: &str) -> Option<u64> {
    get_cbor(map, key).and_then(|v| match v.into_case() {
        CBORCase::Unsigned(n) => Some(n),
        CBORCase::Tagged(_, inner) => match inner.into_case() {
            CBORCase::Unsigned(n) => Some(n),
            _ => None,
        },
        _ => None,
    })
}

fn bytes_cbor(v: &CBOR) -> Result<Vec<u8>, ApplyError> {
    match v.clone().into_case() {
        CBORCase::ByteString(b) => Ok(b.to_vec()),
        _ => Err(ApplyError::BadBody),
    }
}

fn hash32_cbor(v: &CBOR) -> Result<Hash32, ApplyError> {
    let b = bytes_cbor(v)?;
    let arr: [u8; 32] = b.try_into().map_err(|_| ApplyError::BadBody)?;
    Ok(arr)
}

fn roster_list(map: &Map) -> Result<Vec<RosterEntry>, ApplyError> {
    let Some(v) = get_cbor(map, "roster") else {
        return Ok(Vec::new());
    };
    let CBORCase::Array(items) = v.into_case() else {
        return Err(ApplyError::BadBody);
    };
    let mut out = Vec::new();
    for item in items {
        let CBORCase::Map(m) = item.into_case() else {
            return Err(ApplyError::BadBody);
        };
        out.push(parse_roster_entry(&m)?);
    }
    Ok(out)
}

fn parse_roster_entry(m: &Map) -> Result<RosterEntry, ApplyError> {
    let admin = get_cbor(m, "admin")
        .and_then(|v| v.try_into_bool().ok())
        .unwrap_or(false);
    let actor = opt_hash(m, "actor")?;
    let puks = match get_cbor(m, "puks") {
        Some(v) => parse_puks(&v)?,
        None => Vec::new(),
    };
    Ok(RosterEntry { admin, actor, puks })
}

fn parse_puks(v: &CBOR) -> Result<Vec<PublicKey>, ApplyError> {
    let CBORCase::Array(items) = v.clone().into_case() else {
        return Err(ApplyError::BadBody);
    };
    let mut out = Vec::new();
    for item in items {
        let CBORCase::Map(m) = item.into_case() else {
            return Err(ApplyError::BadBody);
        };
        let alg = text_field(&m, "alg").ok_or(ApplyError::BadBody)?;
        if alg != ALG_ED25519 && alg != ALG_P256 {
            return Err(ApplyError::X25519RosterAlg);
        }
        let key = get_cbor(&m, "key").ok_or(ApplyError::BadBody)?;
        out.push(PublicKey {
            alg,
            key: bytes_cbor(&key)?,
        });
    }
    Ok(out)
}

fn wrap_list(map: &Map, sign: Option<Hash32>) -> Result<Vec<Wrap>, ApplyError> {
    let Some(v) = get_cbor(map, "wraps") else {
        return Ok(Vec::new());
    };
    let CBORCase::Array(items) = v.into_case() else {
        return Err(ApplyError::BadBody);
    };
    let mut out = Vec::new();
    for item in items {
        let CBORCase::Map(m) = item.into_case() else {
            return Err(ApplyError::BadBody);
        };
        let alg = text_field(&m, "alg").unwrap_or_default();
        let recipient = get_cbor(&m, "recipient").ok_or(ApplyError::BadBody)?;
        let recipient = bytes_cbor(&recipient)?;
        if let Some(sign) = sign {
            if recipient.as_slice() == sign.as_slice() {
                return Err(ApplyError::SignRecipient);
            }
        }
        let epoch = uint_field(&m, "epoch").unwrap_or(0);
        out.push(Wrap {
            alg,
            recipient,
            epoch,
        });
    }
    Ok(out)
}

fn wraps_contain_sign(wraps: &[Wrap], sign: Option<Hash32>) -> bool {
    let Some(sign) = sign else {
        return false;
    };
    wraps
        .iter()
        .any(|w| w.recipient.as_slice() == sign.as_slice())
}

fn merge_roster(dst: &mut Vec<RosterEntry>, src: Vec<RosterEntry>) {
    for e in src {
        if let Some(actor) = e.actor {
            dst.retain(|x| x.actor != Some(actor));
        }
        dst.push(e);
    }
}

/// Encode a genesis join body for tests.
pub fn encode_genesis(
    actor: Hash32,
    puk_alg: &str,
    puk: &[u8],
    wrap_recipient: &[u8],
) -> Result<Vec<u8>, ApplyError> {
    if puk_alg != ALG_ED25519 && puk_alg != ALG_P256 {
        return Err(ApplyError::X25519RosterAlg);
    }
    let mut puk_map = Map::new();
    puk_map.insert("alg", puk_alg);
    puk_map.insert("key", CBOR::to_byte_string(puk));
    let mut entry = Map::new();
    entry.insert("admin", true);
    entry.insert("actor", CBOR::to_byte_string(actor));
    entry.insert("puks", vec![CBOR::from(puk_map)]);
    let mut wrap = Map::new();
    wrap.insert("alg", "x25519-xchacha20poly1305");
    wrap.insert("recipient", CBOR::to_byte_string(wrap_recipient));
    wrap.insert("epoch", 0u64);
    let mut body = Map::new();
    body.insert("roster", vec![CBOR::from(entry)]);
    body.insert("wraps", vec![CBOR::from(wrap)]);
    body.insert("epoch", 0u64);
    body.insert("profile", "house");
    Ok(CBOR::from(body).to_cbor_data())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use identikey_log::{Author, Hlc, Op, codec};

    use super::*;

    fn op(kind: &str, actor: Hash32, body: Vec<u8>, parents: &[Hash32]) -> Op {
        Op::new(kind, actor, Hlc::new(1_700_000_000_000, 1))
            .with_body(body)
            .with_parents(parents.iter().copied())
    }

    #[test]
    fn genesis_id_is_content_hash() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body = encode_genesis(actor, ALG_ED25519, &[1u8; 32], &[2u8; 32]).unwrap();
        let o = op(KIND_JOIN, actor, body, &[]);
        let want = codec::content_hash(&o).unwrap();
        let mut r = KeyspaceReplica::new();
        let got = r.apply(&o).unwrap();
        assert_eq!(got, want);
        assert_eq!(r.get(&got).unwrap().epoch, 0);
    }

    #[test]
    fn sign_actor_refused() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body = encode_genesis(actor, ALG_ED25519, &[1u8; 32], &[2u8; 32]).unwrap();
        let o = op(KIND_JOIN, actor, body, &[]);
        let mut r = KeyspaceReplica::new();
        r.refuse_sign(actor);
        assert_eq!(r.apply(&o).unwrap_err(), ApplyError::SignActor);
    }

    #[test]
    fn unknown_kind_refused() {
        let author = Author::from_seed(&[7u8; 32]);
        let o = op("guild.join", author.actor(), vec![0xa0], &[]);
        let mut r = KeyspaceReplica::new();
        assert_eq!(r.apply(&o).unwrap_err(), ApplyError::UnknownKind);
    }

    #[test]
    fn change_cannot_carry_wraps() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body = encode_genesis(actor, ALG_ED25519, &[1u8; 32], &[2u8; 32]).unwrap();
        let genesis = op(KIND_JOIN, actor, body, &[]);
        let mut r = KeyspaceReplica::new();
        let id = r.apply(&genesis).unwrap();
        let mut wrap = Map::new();
        wrap.insert("alg", "x25519-xchacha20poly1305");
        wrap.insert("recipient", CBOR::to_byte_string([3u8; 32]));
        wrap.insert("epoch", 1u64);
        let mut m = Map::new();
        m.insert("keyspace", CBOR::to_byte_string(id));
        m.insert("wraps", vec![CBOR::from(wrap)]);
        let change = op(KIND_CHANGE, actor, CBOR::from(m).to_cbor_data(), &[id]);
        assert_eq!(r.apply(&change).unwrap_err(), ApplyError::ChangeWraps);
    }

    #[test]
    fn last_admin_leave_fades() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body = encode_genesis(actor, ALG_ED25519, &[1u8; 32], &[2u8; 32]).unwrap();
        let genesis = op(KIND_JOIN, actor, body, &[]);
        let mut r = KeyspaceReplica::new();
        let id = r.apply(&genesis).unwrap();
        let mut m = Map::new();
        m.insert("keyspace", CBOR::to_byte_string(id));
        m.insert("actor", CBOR::to_byte_string(actor));
        let leave = op(KIND_LEAVE, actor, CBOR::from(m).to_cbor_data(), &[id]);
        r.apply(&leave).unwrap();
        assert!(r.get(&id).unwrap().faded);
        let mut map = Map::new();
        map.insert("keyspace", CBOR::to_byte_string(id));
        map.insert("roster", Vec::<CBOR>::new());
        map.insert("profile", "house");
        let join2 = op(KIND_JOIN, actor, CBOR::from(map).to_cbor_data(), &[id]);
        assert_eq!(r.apply(&join2).unwrap_err(), ApplyError::Faded);
    }

    #[test]
    fn concurrent_begins_neither_live() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body = encode_genesis(actor, ALG_ED25519, &[1u8; 32], &[2u8; 32]).unwrap();
        let genesis = op(KIND_JOIN, actor, body, &[]);
        let mut r = KeyspaceReplica::new();
        let id = r.apply(&genesis).unwrap();

        fn begin_body(id: Hash32, epoch: u64, rec: u8) -> Vec<u8> {
            let mut wrap = Map::new();
            wrap.insert("alg", "x25519-xchacha20poly1305");
            wrap.insert("recipient", CBOR::to_byte_string([rec; 32]));
            wrap.insert("epoch", epoch);
            let mut m = Map::new();
            m.insert("keyspace", CBOR::to_byte_string(id));
            m.insert("epoch", epoch);
            m.insert("wraps", vec![CBOR::from(wrap)]);
            CBOR::from(m).to_cbor_data()
        }

        let b1 = op(KIND_BEGIN, actor, begin_body(id, 1, 9), &[id]);
        let h1 = codec::content_hash(&b1).unwrap();
        r.apply(&b1).unwrap();
        let b2 = op(KIND_BEGIN, actor, begin_body(id, 1, 8), &[id]);
        r.apply(&b2).unwrap();
        assert_eq!(r.pending_begin_count(&id), 0);

        let mut c = Map::new();
        c.insert("keyspace", CBOR::to_byte_string(id));
        c.insert("epoch", 1u64);
        let commit = op(KIND_COMMIT, actor, CBOR::from(c).to_cbor_data(), &[h1]);
        assert_eq!(r.apply(&commit).unwrap_err(), ApplyError::EpochConflict);
    }

    #[test]
    fn x25519_roster_alg_refused() {
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let err = encode_genesis(actor, "x25519", &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert_eq!(err, ApplyError::X25519RosterAlg);
    }
}
