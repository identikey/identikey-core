# Tasks

- [x] Pin `identikey-log` as a git dep (rev + `cargo-deny` `allow-git`, same as `identikey-auth`); type protocol §9 bodies in identikey-keys
- [x] Apply path: genesis `keyspace.join`, then join / change / leave / assign-node / nest / epoch-begin / epoch-commit from a replica
- [x] Refuse IdentiKey Sign as `Op.actor` and wrap-target; PUK selector excludes C2 Sign+Auth; `authorize_elect` is not called on join
- [ ] Optional Postgres cache of applied roster/epoch/wraps; deleting it does not kill the keyspace
- [x] Concurrent `epoch-begin`: apply neither until an admin nacks one or a later begin parents exactly one
- [x] Tests for the ADDED scenarios; `clippy -D warnings`; `cargo deny check`; `cargo sqlx prepare --workspace` if schema changes
