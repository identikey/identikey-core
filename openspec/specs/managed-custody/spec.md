# managed-custody

Living truth for the user store and managed custody in `identikey-keys`.
Folded from `add-keys-store` and `add-c2-c3-exit` on 2026-08-16.

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

### Requirement: C2 to C3 exit ceremony

The system SHALL provide `migrate_c2_to_c3` as the only C2→C3 write. It
SHALL keep the same XID, SHALL destroy `managed_key_blob` (and SHALL NOT
export it), SHALL require a signature over the new document by a key that
holds Elect on the stored C2 document, SHALL persist a document in which
no public key that was Sign+Auth on the stored C2 document retains Sign or
management privileges, SHALL require that some key we do not hold can Sign
and some key we do not hold can Elect (same or different keys), and SHALL
set `resolution_methods` to N≥2 distinct hosts with at least one eTLD+1
outside `{identikey.me, identikey.io}`. Hostless URIs SHALL NOT count as
"not us." The write SHALL be one transaction (one UPDATE of document +
NULL blob + `rung = c3`) plus a consent-log entry (A3/A4 proof,
`action = c2_to_c3`) and a custody event.

#### Scenario: Climb leaves the same XID and no server Sign material

- GIVEN a stored C2 identity with a managed-key blob
- WHEN the user submits a C3 document signed by their Elect private key,
  with a second resolver whose eTLD+1 is not ours
- THEN the stored XID is unchanged, `rung` is `c3`, `managed_key_blob` is
  NULL, and none of the previous Sign+Auth publics retain Sign

#### Scenario: Climb with only our resolvers is refused

- GIVEN a stored C2 identity
- WHEN the submitted document's resolver hosts are only under
  `identikey.me` or `identikey.io`
- THEN the ceremony fails and the row is unchanged (still C2, blob present)

#### Scenario: Our Sign key cannot complete the climb

- GIVEN a stored C2 identity
- WHEN the ceremony is invoked with IdentiKey's Sign key as signer
- THEN the ceremony fails and the row is unchanged

#### Scenario: General document write cannot drop our Sign key

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with a document that is not `is_c2`
- THEN the call fails and the blob and rung are unchanged

#### Scenario: C1 cannot skip to C3 through this ceremony

- GIVEN a stored C1 identity
- WHEN `migrate_c2_to_c3` is invoked
- THEN the ceremony fails and the row is unchanged

#### Scenario: XID change is refused

- GIVEN a stored C2 identity
- WHEN the submitted document's XID differs
- THEN the ceremony fails and the row is unchanged
