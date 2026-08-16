## ADDED Requirements

### Requirement: Durable managed-custody store

The system SHALL persist accounts, passkey credentials, custody records
(including the current XID document), consent-log entries, and custody
events in Postgres via sqlx.

#### Scenario: A new C2 identity survives a new connection

- GIVEN a C2-native XID document and a managed-key blob
- WHEN `KeysStore` creates the managed identity and a new store is opened
  on the same database
- THEN `get_custody` returns the same XID, rung `c2`, and a document that
  `is_c2`

### Requirement: Elect-gated document updates

The system SHALL apply a key-graph document update only when
`authorize_elect` succeeds against the document currently stored for that
XID. A denied update SHALL leave the stored document unchanged.

#### Scenario: IdentiKey's Sign key cannot persist a rotation

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with IdentiKey's Sign key as signer
- THEN the call fails with Elect denied and the stored document bytes are
  identical to before the call

#### Scenario: The user's Elect key can persist a rotation

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with the user's Elect key as signer
  and a new document for the same XID
- THEN the stored document bytes change to the new document

### Requirement: Server boot migrates

`identikey-server` SHALL require `DATABASE_URL`, SHALL run the
`identikey-keys` migrator before serving, and SHALL fail closed if the
URL is missing or not a usable Postgres target. `/health` SHALL remain a
liveness signal and SHALL NOT report pool or key state.

#### Scenario: Missing DATABASE_URL fails at boot

- GIVEN `DATABASE_URL` is unset
- WHEN the server resolves its database configuration
- THEN boot fails with an error that names `DATABASE_URL`
