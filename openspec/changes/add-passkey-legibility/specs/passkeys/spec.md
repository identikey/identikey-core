## ADDED Requirements

### Requirement: Passkey rows name the authenticator

Registration of a passkey SHALL store the authenticator AAGUID when
the ceremony provides one, whether the passkey is backed up, and a
nickname when the client sent one. `GET /account` SHALL list each
non-revoked passkey. The visible label SHALL be the stored nickname
when present, otherwise the provider name from the pinned public
AAGUID metadata list, otherwise the text "Passkey". When that list
entry has an icon, the row SHALL show it. The row SHALL show whether
the passkey is backed up and when it was last used. A missing list
entry, or a metadata list that cannot be read, SHALL still render the
row as "Passkey" and SHALL NOT fail the page. Assertion and
authorization SHALL NOT accept or reject a ceremony based on the
AAGUID.

#### Scenario: Known authenticator shows its name

- GIVEN a passkey whose AAGUID is in the pinned metadata list and no nickname
- WHEN the account holder opens `GET /account`
- THEN the row shows that list entry's name
- AND it shows the backup flag and last-used time

#### Scenario: Nickname wins

- GIVEN a passkey with a stored nickname and a known AAGUID
- WHEN the account holder opens `GET /account`
- THEN the row's label is the nickname

#### Scenario: Unknown AAGUID still lists the passkey

- GIVEN a passkey whose AAGUID is absent from the list
- WHEN the account holder opens `GET /account`
- THEN the row is labeled "Passkey"
- AND the rest of the profile is shown

#### Scenario: AAGUID does not decide login

- GIVEN two passkeys for the same account with different AAGUIDs
- WHEN either one asserts
- THEN the ceremony result does not depend on which AAGUID was stored

## MODIFIED Requirements

### Requirement: First-party signup lands on the account profile

When signup is not an OIDC client journey, a verified registration
SHALL issue an HttpOnly account session and SHALL send the user to
`GET /account`. That page SHALL show the account XID, the current
custody rung, and one row per registered passkey as defined by
"Passkey rows name the authenticator". It SHALL NOT show private
keys, the managed key blob, or a pairwise `sub`. An OIDC signup
(`client_id` present) SHALL still return to `/authorize/passkey`.
`GET /account` without a session SHALL NOT create an account.

#### Scenario: Signup without an app shows the profile

- GIVEN a person completing `GET`/`POST /signup` with no `client_id`
- WHEN attestation verifies
- THEN the response sets an HttpOnly cookie and names `/account`
- AND `GET /account` with that cookie shows the new XID and that passkey's row

#### Scenario: App signup still finishes OIDC

- GIVEN signup started from `/authorize/passkey` with `client_id`
- WHEN attestation verifies
- THEN the page returns to `/authorize/passkey` with the original query

#### Scenario: Profile is not public

- GIVEN no account session cookie
- WHEN `GET /account`
- THEN the response is not the profile and no account is inserted
