# Tasks

- [x] `KeysStore` connects and runs `MIGRATOR`
- [x] Persist account, passkey credential, custody record, consent entry
- [x] `apply_document_update` authorizes against the stored document; Elect-denied writes do not land
- [x] `identikey-server` fails closed without `DATABASE_URL`, migrates at boot, holds the store
- [x] Tests against real Postgres; clippy `-D warnings`; `cargo deny check`
