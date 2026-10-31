---
spike_id: password-hasher
hypothesis_id: password-hasher
source_synthesis: null
run_at: 2026-10-31T05:14:35-07:00
time_spent_min: 15
verdict: go
version-pinned: argon2@0.5.3
---

# Spike: Argon2id at a 19 MiB floor fits a small OpenID provider

## Claim Tested

Argon2id with m=19456 KiB (19 MiB), t=2, p=1 hashes and verifies a password on this machine in under one second, keeps the process under 256 MiB, and stores those parameters in the hash string. A wrong password is rejected.

## Minimal Test

A standalone crate at `docs/spikes/password-hasher`, outside the workspace, depends on `argon2` 0.5.3. It hashes one passphrase with a fixed 16-byte salt, parses the PHC string, verifies the passphrase, and rejects a different one. Release mode. The program exits non-zero if the budget fails.

## Evidence

`evidence.log` from `cargo run --release --offline`:

- algorithm `argon2id`, parameters `m=19456,t=2,p=1` round-trip from the hash
- PHC string is 97 bytes
- hash 23.0 ms, verify 21.7 ms
- wrong password rejected
- VmRSS before the hash 2520 KiB, VmHWM after 22048 KiB (about 21.5 MiB)

## Verdict: go

The 19 MiB, two-iteration, one-lane Argon2id floor is a login check on this machine, not a big-server recipe. The hash carries its own settings, so a later deployment can raise them without a second code path. This does not implement the password credential. Act on `add-password-credential` still waits for human activation.
