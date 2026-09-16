## ADDED Requirements

### Requirement: Access-node login wraps the caller's PUK

After a successful identikey login, identikey-keys SHALL apply a
`keyspace.join` on the access-node keyspace the node holds, wrapping
the PTK to `c2_wrap_recipient` of the stored document (the user's
X25519 encapsulation public). That join SHALL merge wrap recipients
and SHALL NOT change the PTK epoch. IdentiKey Sign+Auth SHALL NOT be
a wrap recipient. A house keyspace SHALL NOT accept `wrap_login`.

#### Scenario: Login wrap does not rotate the access-node PTK

- GIVEN an access-node keyspace nested on a house keyspace at epoch N
- WHEN identikey-keys applies wrap-on-login for a C2 member
- THEN the wrap-list includes that member's X25519 encapsulation public
  and the epoch is still N

#### Scenario: Sign+Auth is not wrapped on login

- GIVEN a stored C2 identity
- WHEN wrap-on-login is asked to use IdentiKey's Sign+Auth public as
  the recipient
- THEN the op is refused and the wrap-list is unchanged

#### Scenario: House profile refuses wrap-on-login

- GIVEN a house keyspace
- WHEN wrap-on-login is called on that keyspace
- THEN the op is refused
