//! Isolated check: Argon2id at a small-machine floor.
//! m = 19456 KiB (19 MiB), t = 2, p = 1. Not production code.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use std::fs;
use std::time::Instant;

const M_KIB: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const LOGIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(1000);
const PROCESS_RSS_CEILING: u64 = 256 * 1024;

fn rss_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn hwm_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn main() {
    let params = Params::new(M_KIB, T_COST, P_COST, None).expect("params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::encode_b64(b"spike-salt-16byt").expect("salt");
    let password = b"correct horse battery staple";

    let before = rss_kib();
    let started = Instant::now();
    let hash = argon
        .hash_password(password, &salt)
        .expect("hash")
        .to_string();
    let hash_ms = started.elapsed();

    let parsed = PasswordHash::new(&hash).expect("parse");
    let verify_started = Instant::now();
    argon
        .verify_password(password, &parsed)
        .expect("verify");
    let verify_ms = verify_started.elapsed();
    let wrong = argon
        .verify_password(b"wrong horse battery staple", &parsed)
        .is_err();
    let after_hwm = hwm_kib();

    let ident = parsed.algorithm.as_str();
    let m = parsed
        .params
        .get("m")
        .expect("m")
        .to_string();
    let t = parsed.params.get("t").expect("t").to_string();
    let p = parsed.params.get("p").expect("p").to_string();

    println!("algorithm={ident}");
    println!("phc={hash}");
    println!("phc_bytes={}", hash.len());
    println!("param_m={m}");
    println!("param_t={t}");
    println!("param_p={p}");
    println!("hash_ms={}", hash_ms.as_secs_f64() * 1000.0);
    println!("verify_ms={}", verify_ms.as_secs_f64() * 1000.0);
    println!("wrong_rejected={wrong}");
    println!("rss_before_kib={before}");
    println!("hwm_kib={after_hwm}");

    assert_eq!(ident, "argon2id");
    assert_eq!(m, M_KIB.to_string());
    assert_eq!(t, T_COST.to_string());
    assert_eq!(p, P_COST.to_string());
    assert!(wrong, "a wrong password verified");
    assert!(hash.len() < 256, "PHC string does not fit a short text column");
    assert!(hash_ms < LOGIN_BUDGET, "hash exceeded 1s: {hash_ms:?}");
    assert!(
        verify_ms < LOGIN_BUDGET,
        "verify exceeded 1s: {verify_ms:?}"
    );
    assert!(
        after_hwm < PROCESS_RSS_CEILING,
        "process high-water {after_hwm} KiB exceeded {PROCESS_RSS_CEILING} KiB"
    );
}
