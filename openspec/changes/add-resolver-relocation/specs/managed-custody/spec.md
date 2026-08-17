## ADDED Requirements

### Requirement: Post-climb resolver relocation

On a stored C3 or C4 row, `apply_document_update` SHALL persist a new
document for the same XID when `authorize_elect` succeeds and the new
document's `resolution_methods` satisfy the same host rules as the
C2→C3 ceremony (N≥2 distinct HTTP(S) hosts, at least one eTLD+1
outside `{identikey.me, identikey.io}`, hostless URIs do not count as
"not us", localhost and RFC1918 refused). The write SHALL NOT change
`rung` or `managed_key_blob`. A refused update SHALL leave the stored
document, rung, and blob unchanged. A C2 row SHALL still refuse a
document that is not `is_c2`.

#### Scenario: C3 user can replace a resolver

- GIVEN a stored C3 identity with our host and `resolver.example`
- WHEN `apply_document_update` is called with the user's Elect key and
  a document that replaces `resolver.example` with `backup.example`
  and still includes one of our hosts
- THEN the stored document bytes change, `rung` is still `c3`, and
  `managed_key_blob` is still NULL

#### Scenario: Dropping the last not-us host is refused

- GIVEN a stored C3 identity whose only not-us host is `resolver.example`
- WHEN `apply_document_update` is called with a document whose
  resolver hosts are only under `identikey.me` or `identikey.io`
- THEN the call fails and the stored document bytes are unchanged

#### Scenario: C2 still cannot leave is_c2 this way

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with a document that is not
  `is_c2`
- THEN the call fails and the blob and rung are unchanged
