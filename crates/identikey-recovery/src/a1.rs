//! Library-only A1 factors. Store and directory implementations are trusted ports.
use std::{collections::HashMap, sync::Mutex};

pub use bc_components::XID;
pub use identikey_keys::CustodyRung;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::AccountRecoveryProof;

/// Fixed width makes the hash encoding `id || secret` unambiguous.
pub type ChallengeId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    Email,
    Sms,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Bootstrap,
    Recover(XID),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub channel: Channel,
    pub destination: String,
    pub purpose: Purpose,
}

#[derive(Debug, thiserror::Error)]
pub enum FactorError {
    #[error("factor store failed")]
    Store,
    #[error("directory failed")]
    Directory,
    #[error("destination or custody refused")]
    Refused,
    #[error("entropy unavailable")]
    Entropy,
    #[error("challenge id collision")]
    Collision,
}

/// Must resolve the exact channel/destination/purpose, from trusted account data.
/// Bootstrap returns the canonical destination with no XID; recover supplies its XID.
pub trait Directory: Send + Sync {
    fn lookup(
        &self,
        channel: Channel,
        destination: &str,
        recovering: bool,
    ) -> Result<Option<Binding>, FactorError>;
    fn rung(&self, xid: XID) -> Result<Option<CustodyRung>, FactorError>;
}

/// Stored state contains a digest, never the delivered secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Factor {
    pub binding: Binding,
    pub secret_hash: [u8; 32],
    pub expires_at: OffsetDateTime,
    pub wrong_attempts: u8,
    pub consumed: bool,
}

/// Implementations must insert without replacing an existing id. `transition`
/// must evaluate the closure exactly once against current state and atomically
/// commit its replacement before returning. On error no state is committed and
/// no result may escape. Serialize concurrent transitions for the same id.
pub trait FactorStore: Send + Sync {
    fn insert(&self, id: ChallengeId, factor: Factor) -> Result<(), FactorError>;
    fn transition<R>(
        &self,
        id: ChallengeId,
        apply: impl FnOnce(&Factor) -> Result<(Factor, R), FactorError>,
    ) -> Result<Option<R>, FactorError>;
}

#[derive(Default)]
pub struct MemoryFactorStore {
    factors: Mutex<HashMap<ChallengeId, Factor>>,
}

impl FactorStore for MemoryFactorStore {
    fn insert(&self, id: ChallengeId, factor: Factor) -> Result<(), FactorError> {
        let mut factors = self.factors.lock().map_err(|_| FactorError::Store)?;
        match factors.entry(id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(factor);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(FactorError::Collision),
        }
    }
    fn transition<R>(
        &self,
        id: ChallengeId,
        apply: impl FnOnce(&Factor) -> Result<(Factor, R), FactorError>,
    ) -> Result<Option<R>, FactorError> {
        let mut factors = self.factors.lock().map_err(|_| FactorError::Store)?;
        let Some(current) = factors.get_mut(&id) else {
            return Ok(None);
        };
        let (next, result) = apply(current)?;
        *current = next;
        Ok(Some(result))
    }
}

/// Secret delivery payload. Debug intentionally redacts the secret.
pub struct IssuedFactor {
    pub id: ChallengeId,
    pub secret: Vec<u8>,
}
impl std::fmt::Debug for IssuedFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedFactor")
            .field("id", &self.id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

fn hash(id: &ChallengeId, secret: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(id);
    hash.update(secret);
    hash.finalize().into()
}

fn binding<D: Directory>(
    directory: &D,
    channel: Channel,
    destination: &str,
    purpose: Purpose,
) -> Result<Binding, FactorError> {
    let found = directory
        .lookup(channel, destination, matches!(purpose, Purpose::Recover(_)))?
        .ok_or(FactorError::Refused)?;
    if found.channel != channel || found.destination != destination || found.purpose != purpose {
        return Err(FactorError::Refused);
    }
    if let Purpose::Recover(xid) = purpose {
        if !matches!(
            directory.rung(xid)?,
            Some(CustodyRung::C1 | CustodyRung::C2)
        ) {
            return Err(FactorError::Refused);
        }
    }
    Ok(found)
}

/// Issues only after entropy and insertion succeed. The caller delivers the secret.
pub fn begin<S: FactorStore, D: Directory>(
    store: &S,
    directory: &D,
    channel: Channel,
    destination: &str,
    purpose: Purpose,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<IssuedFactor, FactorError> {
    begin_using(
        store,
        directory,
        channel,
        destination,
        purpose,
        now,
        expires_at,
        |bytes| getrandom::fill(bytes).map_err(|_| FactorError::Entropy),
    )
}

// Private injection keeps deterministic and failing entropy out of the public API.
#[allow(clippy::too_many_arguments)]
fn begin_using<S: FactorStore, D: Directory>(
    store: &S,
    directory: &D,
    channel: Channel,
    destination: &str,
    purpose: Purpose,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
    mut random: impl FnMut(&mut [u8]) -> Result<(), FactorError>,
) -> Result<IssuedFactor, FactorError> {
    if expires_at <= now {
        return Err(FactorError::Refused);
    }
    let binding = binding(directory, channel, destination, purpose)?;
    let mut id = [0; 32];
    random(&mut id)?;
    let secret = match channel {
        Channel::Email => {
            let mut bytes = vec![0; 32];
            random(&mut bytes)?;
            bytes
        }
        Channel::Sms => {
            let mut digits = Vec::with_capacity(6);
            while digits.len() < 6 {
                let mut byte = [0];
                random(&mut byte)?;
                // 250 is a multiple of ten: rejection avoids modulo bias.
                if let Some(value) = byte.first().copied().filter(|v| *v < 250) {
                    digits.push(b'0' + value % 10);
                }
            }
            digits
        }
    };
    store.insert(
        id,
        Factor {
            binding,
            secret_hash: hash(&id, &secret),
            expires_at,
            wrong_attempts: 0,
            consumed: false,
        },
    )?;
    Ok(IssuedFactor { id, secret })
}

/// Only committed consumption can create a proof. Directory refusals preserve factors.
pub fn finish<S: FactorStore, D: Directory>(
    store: &S,
    directory: &D,
    id: ChallengeId,
    secret: &[u8],
    now: OffsetDateTime,
) -> Result<Option<AccountRecoveryProof>, FactorError> {
    let presented = hash(&id, secret);
    let committed = store.transition(id, |current| {
        let mut next = current.clone();
        if current.consumed || now >= current.expires_at || current.wrong_attempts >= 5 {
            return Ok((next, None));
        }
        if matches!(current.binding.purpose, Purpose::Recover(_)) {
            binding(
                directory,
                current.binding.channel,
                &current.binding.destination,
                current.binding.purpose,
            )?;
        }
        if bool::from(current.secret_hash.ct_eq(&presented)) {
            next.consumed = true;
            Ok((next, Some(current.binding.clone())))
        } else {
            if current.binding.channel == Channel::Sms {
                next.wrong_attempts += 1;
                if next.wrong_attempts == 5 {
                    next.consumed = true;
                }
            }
            Ok((next, None))
        }
    })?;
    Ok(committed.flatten().map(|binding| AccountRecoveryProof {
        binding: Some(binding),
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptanceError<E> {
    #[error("proof or current directory binding refused")]
    Refused,
    #[error(transparent)]
    Directory(FactorError),
    #[error("acceptance callback failed")]
    Callback(E),
}

/// Consumes the proof before checking purpose or running trusted integration code.
pub fn accept_bootstrap<E>(
    proof: &mut AccountRecoveryProof,
    create: impl FnOnce(&Binding) -> Result<(), E>,
) -> Result<(), AcceptanceError<E>> {
    let bound = proof.binding.take().ok_or(AcceptanceError::Refused)?;
    if bound.purpose != Purpose::Bootstrap {
        return Err(AcceptanceError::Refused);
    }
    create(&bound).map_err(AcceptanceError::Callback)
}

/// Revalidates destination ownership and current custody; refusal consumes the proof.
pub fn accept_recover<D: Directory, E>(
    proof: &mut AccountRecoveryProof,
    directory: &D,
    requested_xid: XID,
    enroll: impl FnOnce(&Binding, XID) -> Result<(), E>,
) -> Result<(), AcceptanceError<E>> {
    let bound = proof.binding.take().ok_or(AcceptanceError::Refused)?;
    if bound.purpose != Purpose::Recover(requested_xid) {
        return Err(AcceptanceError::Refused);
    }
    binding(directory, bound.channel, &bound.destination, bound.purpose)
        .map_err(AcceptanceError::Directory)?;
    enroll(&bound, requested_xid).map_err(AcceptanceError::Callback)
}

#[cfg(test)]
mod tests;
