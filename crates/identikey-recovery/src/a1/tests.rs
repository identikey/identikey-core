#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;
use std::sync::{
    Barrier, RwLock,
    atomic::{AtomicBool, Ordering},
};
use time::Duration;

struct TestDirectory {
    owner: RwLock<Option<XID>>,
    rung: RwLock<CustodyRung>,
    failed: AtomicBool,
}
impl TestDirectory {
    fn new() -> Self {
        Self {
            owner: RwLock::new(Some(xid(1))),
            rung: RwLock::new(CustodyRung::C2),
            failed: AtomicBool::new(false),
        }
    }
}
impl Directory for TestDirectory {
    fn lookup(
        &self,
        channel: Channel,
        destination: &str,
        recovering: bool,
    ) -> Result<Option<Binding>, FactorError> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(FactorError::Directory);
        }
        let purpose = if recovering {
            let Some(owner) = *self.owner.read().unwrap() else {
                return Ok(None);
            };
            Purpose::Recover(owner)
        } else {
            Purpose::Bootstrap
        };
        Ok(Some(Binding {
            channel,
            destination: destination.into(),
            purpose,
        }))
    }
    fn rung(&self, _: XID) -> Result<Option<CustodyRung>, FactorError> {
        Ok(Some(*self.rung.read().unwrap()))
    }
}
fn xid(n: u8) -> XID {
    XID::from_data([n; 32])
}
fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}
fn issue<S: FactorStore>(
    store: &S,
    directory: &TestDirectory,
    channel: Channel,
    purpose: Purpose,
) -> IssuedFactor {
    begin(
        store,
        directory,
        channel,
        "bound destination",
        purpose,
        now(),
        now() + Duration::minutes(5),
    )
    .unwrap()
}
fn proof<S: FactorStore>(
    store: &S,
    directory: &TestDirectory,
    channel: Channel,
    purpose: Purpose,
) -> AccountRecoveryProof {
    let issued = issue(store, directory, channel, purpose);
    finish(store, directory, issued.id, &issued.secret, now())
        .unwrap()
        .unwrap()
}
fn wrong(secret: &[u8]) -> Vec<u8> {
    let mut result = secret.to_vec();
    result[0] = if result[0] == b'0' { b'1' } else { b'0' };
    result
}

#[test]
fn a1_factor_hash_format_and_expiry_replay() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    for channel in [Channel::Email, Channel::Sms] {
        let issued = issue(&store, &directory, channel, Purpose::Bootstrap);
        assert_eq!(
            issued.secret.len(),
            if channel == Channel::Email { 32 } else { 6 }
        );
        if channel == Channel::Sms {
            assert!(issued.secret.iter().all(u8::is_ascii_digit));
        }
        let stored = store.factors.lock().unwrap()[&issued.id].clone();
        let mut bytes = issued.id.to_vec();
        bytes.extend_from_slice(&issued.secret);
        assert_eq!(
            stored.secret_hash.as_slice(),
            Sha256::digest(bytes).as_slice()
        );
        assert!(!format!("{issued:?}").contains(&format!("{:?}", issued.secret)));
        let result = finish(&store, &directory, issued.id, &issued.secret, now())
            .unwrap()
            .unwrap();
        assert_eq!(result.binding(), Some(&stored.binding));
        assert!(
            finish(&store, &directory, issued.id, &issued.secret, now())
                .unwrap()
                .is_none()
        );
        let expired = issue(&store, &directory, channel, Purpose::Bootstrap);
        assert!(
            finish(
                &store,
                &directory,
                expired.id,
                &expired.secret,
                now() + Duration::minutes(5)
            )
            .unwrap()
            .is_none()
        );
    }
    assert!(
        finish(&store, &directory, [0; 32], b"unknown", now())
            .unwrap()
            .is_none()
    );
    assert!(
        begin(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now()
        )
        .is_err()
    );
}

#[test]
fn a1_factor_attempt_budgets() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    let email = issue(&store, &directory, Channel::Email, Purpose::Bootstrap);
    for _ in 0..10 {
        assert!(
            finish(&store, &directory, email.id, &wrong(&email.secret), now())
                .unwrap()
                .is_none()
        );
    }
    assert!(
        finish(&store, &directory, email.id, &email.secret, now())
            .unwrap()
            .is_some()
    );
    let sms = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
    assert!(
        finish(&store, &directory, sms.id, &wrong(&sms.secret), now())
            .unwrap()
            .is_none()
    );
    assert!(
        finish(&store, &directory, sms.id, &sms.secret, now())
            .unwrap()
            .is_some()
    );
    let sms = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
    for _ in 0..5 {
        assert!(
            finish(&store, &directory, sms.id, &wrong(&sms.secret), now())
                .unwrap()
                .is_none()
        );
    }
    assert!(
        finish(&store, &directory, sms.id, &sms.secret, now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn a1_factor_two_concurrent_successes() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    let issued = issue(&store, &directory, Channel::Email, Purpose::Bootstrap);
    let barrier = Barrier::new(2);
    let count = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    finish(&store, &directory, issued.id, &issued.secret, now())
                        .unwrap()
                        .is_some()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(count, 1);
}

#[test]
fn a1_factor_concurrent_wrong_attempts() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    let issued = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
    let barrier = Barrier::new(5);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..5)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    assert!(
                        finish(&store, &directory, issued.id, &wrong(&issued.secret), now())
                            .unwrap()
                            .is_none()
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert_eq!(store.factors.lock().unwrap()[&issued.id].wrong_attempts, 5);
    assert!(
        finish(&store, &directory, issued.id, &issued.secret, now())
            .unwrap()
            .is_none()
    );
}

// Both contenders run on distinct threads. The gate forces each possible commit order.
#[test]
fn a1_factor_fifth_failure_race_both_commit_orders() {
    for failure_first in [true, false] {
        let store = MemoryFactorStore::default();
        let directory = TestDirectory::new();
        let issued = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
        for _ in 0..4 {
            finish(&store, &directory, issued.id, &wrong(&issued.secret), now()).unwrap();
        }
        let (sent, received) = std::sync::mpsc::channel();
        let won = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                let secret = if failure_first {
                    wrong(&issued.secret)
                } else {
                    issued.secret.clone()
                };
                let won = finish(&store, &directory, issued.id, &secret, now())
                    .unwrap()
                    .is_some();
                sent.send(()).unwrap();
                won
            });
            let store = &store;
            let directory = &directory;
            let issued = &issued;
            let second = scope.spawn(move || {
                received.recv().unwrap();
                let secret = if failure_first {
                    issued.secret.clone()
                } else {
                    wrong(&issued.secret)
                };
                finish(store, directory, issued.id, &secret, now())
                    .unwrap()
                    .is_some()
            });
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });
        assert_eq!(won, usize::from(!failure_first));
        let factor = store.factors.lock().unwrap()[&issued.id].clone();
        assert!(factor.consumed);
        assert_eq!(factor.wrong_attempts, if failure_first { 5 } else { 4 });
    }
}

#[test]
fn a1_factor_fifth_failure_contends_with_success() {
    for _ in 0..32 {
        let store = MemoryFactorStore::default();
        let directory = TestDirectory::new();
        let issued = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
        for _ in 0..4 {
            finish(&store, &directory, issued.id, &wrong(&issued.secret), now()).unwrap();
        }
        let barrier = Barrier::new(2);
        let succeeded = std::thread::scope(|scope| {
            let matching = scope.spawn(|| {
                barrier.wait();
                finish(&store, &directory, issued.id, &issued.secret, now())
                    .unwrap()
                    .is_some()
            });
            let wrong = scope.spawn(|| {
                barrier.wait();
                assert!(
                    finish(&store, &directory, issued.id, &wrong(&issued.secret), now())
                        .unwrap()
                        .is_none()
                );
            });
            wrong.join().unwrap();
            matching.join().unwrap()
        });
        let factor = store.factors.lock().unwrap()[&issued.id].clone();
        assert!(factor.consumed);
        assert_eq!(factor.wrong_attempts, if succeeded { 4 } else { 5 });
        assert!(
            finish(&store, &directory, issued.id, &issued.secret, now())
                .unwrap()
                .is_none()
        );
    }
}

struct FailingStore {
    inner: MemoryFactorStore,
    fail: AtomicBool,
}
impl FactorStore for FailingStore {
    fn insert(&self, id: ChallengeId, factor: Factor) -> Result<(), FactorError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(FactorError::Store);
        }
        self.inner.insert(id, factor)
    }
    fn transition<R>(
        &self,
        id: ChallengeId,
        apply: impl FnOnce(&Factor) -> Result<(Factor, R), FactorError>,
    ) -> Result<Option<R>, FactorError> {
        self.inner.transition(id, |current| {
            let result = apply(current)?;
            if self.fail.load(Ordering::SeqCst) {
                return Err(FactorError::Store);
            }
            Ok(result)
        })
    }
}
#[test]
fn a1_factor_store_errors_never_issue_or_consume() {
    let store = FailingStore {
        inner: MemoryFactorStore::default(),
        fail: AtomicBool::new(false),
    };
    let directory = TestDirectory::new();
    let issued = issue(&store, &directory, Channel::Sms, Purpose::Bootstrap);
    store.fail.store(true, Ordering::SeqCst);
    assert!(
        begin(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now() + Duration::minutes(1)
        )
        .is_err()
    );
    assert!(finish(&store, &directory, issued.id, &issued.secret, now()).is_err());
    assert!(finish(&store, &directory, issued.id, &wrong(&issued.secret), now()).is_err());
    let unchanged = store.inner.factors.lock().unwrap()[&issued.id].clone();
    assert_eq!(unchanged.wrong_attempts, 0);
    assert!(!unchanged.consumed);
    store.fail.store(false, Ordering::SeqCst);
    assert!(
        finish(&store, &directory, issued.id, &issued.secret, now())
            .unwrap()
            .is_some()
    );
}

#[test]
fn a1_factor_directory_binding_at_begin_finish_and_accept() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    assert!(
        begin(
            &store,
            &directory,
            Channel::Sms,
            "d",
            Purpose::Recover(xid(2)),
            now(),
            now() + Duration::minutes(1)
        )
        .is_err()
    );
    for owner in [None, Some(xid(2))] {
        let issued = issue(&store, &directory, Channel::Sms, Purpose::Recover(xid(1)));
        *directory.owner.write().unwrap() = owner;
        assert!(finish(&store, &directory, issued.id, &issued.secret, now()).is_err());
        assert!(!store.factors.lock().unwrap()[&issued.id].consumed);
        *directory.owner.write().unwrap() = Some(xid(1));
        let mut proof = finish(&store, &directory, issued.id, &issued.secret, now())
            .unwrap()
            .unwrap();
        *directory.owner.write().unwrap() = owner;
        assert!(
            accept_recover(&mut proof, &directory, xid(1), |_, _| -> Result<(), ()> {
                panic!("revoked binding ran")
            })
            .is_err()
        );
        assert!(proof.binding().is_none());
        *directory.owner.write().unwrap() = Some(xid(1));
        assert!(
            accept_recover(&mut proof, &directory, xid(1), |_, _| -> Result<(), ()> {
                panic!("second acceptance ran")
            })
            .is_err()
        );
    }
    let mut proof = proof(&store, &directory, Channel::Email, Purpose::Recover(xid(1)));
    accept_recover(
        &mut proof,
        &directory,
        xid(1),
        |bound, owner| -> Result<(), ()> {
            assert_eq!(bound.destination, "bound destination");
            assert_eq!(bound.channel, Channel::Email);
            assert_eq!(owner, xid(1));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn a1_factor_custody_rechecked_at_all_stages() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    for rung in [CustodyRung::C0, CustodyRung::C3, CustodyRung::C4] {
        let issued = issue(&store, &directory, Channel::Sms, Purpose::Recover(xid(1)));
        let mut accepted = proof(&store, &directory, Channel::Email, Purpose::Recover(xid(1)));
        *directory.rung.write().unwrap() = rung;
        assert!(
            begin(
                &store,
                &directory,
                Channel::Email,
                "d",
                Purpose::Recover(xid(1)),
                now(),
                now() + Duration::minutes(1)
            )
            .is_err()
        );
        assert!(finish(&store, &directory, issued.id, &issued.secret, now()).is_err());
        assert!(!store.factors.lock().unwrap()[&issued.id].consumed);
        assert!(
            accept_recover(
                &mut accepted,
                &directory,
                xid(1),
                |_, _| -> Result<(), ()> { panic!("custody bypass") }
            )
            .is_err()
        );
        assert!(accepted.binding().is_none());
        *directory.rung.write().unwrap() = CustodyRung::C1;
        assert!(
            finish(&store, &directory, issued.id, &issued.secret, now())
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn a1_factor_purpose_single_use_errors_and_legacy_access() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    let mut bootstrap = proof(&store, &directory, Channel::Email, Purpose::Bootstrap);
    let mut count = 0;
    assert!(
        accept_bootstrap(&mut bootstrap, |bound| {
            count += 1;
            assert_eq!(bound.destination, "bound destination");
            Err(())
        })
        .is_err()
    );
    assert!(
        accept_bootstrap(&mut bootstrap, |_| {
            count += 1;
            Ok::<_, ()>(())
        })
        .is_err()
    );
    assert_eq!(count, 1);
    let mut recover = proof(&store, &directory, Channel::Sms, Purpose::Recover(xid(1)));
    assert!(accept_recover(&mut recover, &directory, xid(1), |_, _| Err(())).is_err());
    assert!(
        accept_recover(&mut recover, &directory, xid(1), |_, _| -> Result<(), ()> {
            panic!("callback replay")
        })
        .is_err()
    );
    let mut bootstrap = proof(&store, &directory, Channel::Email, Purpose::Bootstrap);
    assert!(
        accept_recover(
            &mut bootstrap,
            &directory,
            xid(1),
            |_, _| -> Result<(), ()> { panic!("wrong purpose") }
        )
        .is_err()
    );
    let mut recover = proof(&store, &directory, Channel::Sms, Purpose::Recover(xid(1)));
    assert!(
        accept_bootstrap(&mut recover, |_| -> Result<(), ()> {
            panic!("wrong purpose")
        })
        .is_err()
    );
    let mut recover = proof(&store, &directory, Channel::Sms, Purpose::Recover(xid(1)));
    assert!(
        accept_recover(&mut recover, &directory, xid(2), |_, _| -> Result<(), ()> {
            panic!("retargeted")
        })
        .is_err()
    );
    assert!(
        crate::restore_access(proof(
            &store,
            &directory,
            Channel::Email,
            Purpose::Bootstrap
        ))
        .is_none()
    );
    let mut bootstrap = proof(&store, &directory, Channel::Email, Purpose::Bootstrap);
    accept_bootstrap(&mut bootstrap, |_| Ok::<_, ()>(())).unwrap();
}

#[test]
fn a1_factor_generation_rejection_leading_zeros_collision_and_failure() {
    let store = MemoryFactorStore::default();
    let directory = TestDirectory::new();
    let mut samples = vec![b'9' - b'0', 8, 7, 6, 5, 0, 255, 250].into_iter().rev();
    let issued = begin_using(
        &store,
        &directory,
        Channel::Sms,
        "d",
        Purpose::Bootstrap,
        now(),
        now() + Duration::minutes(1),
        |bytes| {
            if bytes.len() == 32 {
                bytes.fill(3);
            } else {
                bytes[0] = samples.next().unwrap();
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(issued.secret, b"056789");
    finish(&store, &directory, issued.id, &wrong(&issued.secret), now()).unwrap();
    assert!(matches!(
        begin_using(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now() + Duration::minutes(1),
            |bytes| {
                bytes.fill(3);
                Ok(())
            }
        ),
        Err(FactorError::Collision)
    ));
    assert_eq!(store.factors.lock().unwrap()[&issued.id].wrong_attempts, 1);
    assert!(
        finish(&store, &directory, issued.id, &issued.secret, now())
            .unwrap()
            .is_some()
    );
    let count = store.factors.lock().unwrap().len();
    assert!(
        begin_using(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now() + Duration::minutes(1),
            |_| Err(FactorError::Entropy)
        )
        .is_err()
    );
    let mut calls = 0;
    assert!(
        begin_using(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now() + Duration::minutes(1),
            |bytes| {
                calls += 1;
                bytes.fill(4);
                if calls == 2 {
                    Err(FactorError::Entropy)
                } else {
                    Ok(())
                }
            }
        )
        .is_err()
    );
    assert_eq!(store.factors.lock().unwrap().len(), count);
    directory.failed.store(true, Ordering::SeqCst);
    assert!(
        begin(
            &store,
            &directory,
            Channel::Email,
            "d",
            Purpose::Bootstrap,
            now(),
            now() + Duration::minutes(1)
        )
        .is_err()
    );
}

#[test]
fn a1_factor_directory_cannot_substitute_binding_fields() {
    struct Substitute(Binding);
    impl Directory for Substitute {
        fn lookup(&self, _: Channel, _: &str, _: bool) -> Result<Option<Binding>, FactorError> {
            Ok(Some(self.0.clone()))
        }
        fn rung(&self, _: XID) -> Result<Option<CustodyRung>, FactorError> {
            Ok(Some(CustodyRung::C2))
        }
    }
    let store = MemoryFactorStore::default();
    for bound in [
        Binding {
            channel: Channel::Sms,
            destination: "d".into(),
            purpose: Purpose::Bootstrap,
        },
        Binding {
            channel: Channel::Email,
            destination: "another destination".into(),
            purpose: Purpose::Bootstrap,
        },
        Binding {
            channel: Channel::Email,
            destination: "d".into(),
            purpose: Purpose::Recover(xid(1)),
        },
    ] {
        assert!(
            begin(
                &store,
                &Substitute(bound),
                Channel::Email,
                "d",
                Purpose::Bootstrap,
                now(),
                now() + Duration::minutes(1)
            )
            .is_err()
        );
    }
    assert!(store.factors.lock().unwrap().is_empty());
    let directory = TestDirectory::new();
    let issued = issue(&store, &directory, Channel::Email, Purpose::Recover(xid(1)));
    directory.failed.store(true, Ordering::SeqCst);
    assert!(finish(&store, &directory, issued.id, &issued.secret, now()).is_err());
    assert!(!store.factors.lock().unwrap()[&issued.id].consumed);
    directory.failed.store(false, Ordering::SeqCst);
    let mut proof = finish(&store, &directory, issued.id, &issued.secret, now())
        .unwrap()
        .unwrap();
    directory.failed.store(true, Ordering::SeqCst);
    assert!(
        accept_recover(&mut proof, &directory, xid(1), |_, _| -> Result<(), ()> {
            panic!("directory failure ran callback")
        })
        .is_err()
    );
    assert!(proof.binding().is_none());
}
