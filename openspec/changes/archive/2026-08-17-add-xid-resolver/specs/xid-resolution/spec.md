## ADDED Requirements

### Requirement: Convenience well-known resolver

`identikey-server` SHALL serve the stored XID document at
`GET /.well-known/xid/{xid}` as an availability service. `{xid}` SHALL
be 64 lowercase hex characters. The 200 body SHALL be the stored
`xid_document` bytes and SHALL NOT be re-signed by the server. Unknown
or malformed XIDs SHALL return 404. `/health` SHALL remain a liveness
signal and SHALL NOT report resolver or key state.

#### Scenario: A stored document is fetchable by XID

- GIVEN a custody row for XID H
- WHEN `GET /.well-known/xid/{H}` is called
- THEN the response is 200 and the body equals the stored document bytes

#### Scenario: Missing XID is 404

- GIVEN no custody row for XID H
- WHEN `GET /.well-known/xid/{H}` is called
- THEN the response is 404

#### Scenario: Malformed XID is 404

- GIVEN any path segment that is not 64 lowercase hex characters
- WHEN `GET /.well-known/xid/{segment}` is called
- THEN the response is 404

### Requirement: Short TTL and revalidation signal

The well-known response SHALL advertise `Cache-Control: max-age=60,
must-revalidate` and SHALL set `ETag` to the hex SHA-256 of the body.
A GET with a matching `If-None-Match` SHALL return 304 when the stored
document is unchanged. After a successful document write for that XID,
a subsequent GET SHALL return the new bytes and a different ETag.

#### Scenario: Rotation is visible without waiting out the TTL

- GIVEN a 200 response with ETag T for XID H
- WHEN the stored document for H is replaced
- THEN `GET /.well-known/xid/{H}` returns the new bytes and an ETag
  other than T

#### Scenario: Unchanged document revalidates

- GIVEN a 200 response with ETag T for XID H and no later write
- WHEN `GET /.well-known/xid/{H}` is called with `If-None-Match: T`
- THEN the response is 304
