## ADDED Requirements

### Requirement: Passkey rows name the authenticator

Registration of a passkey SHALL store the authenticator AAGUID when
the ceremony provides one, the registration-time backup state (the
BS bit, not backup eligibility), and a nickname when the trimmed
client value is nonempty. A later assertion SHALL NOT refresh that
backup bit. `GET /account` SHALL list each non-revoked passkey. The
visible label SHALL be the trimmed nonempty nickname when one is
stored, including when the AAGUID is absent from the pinned list or
that list cannot be read. Otherwise the label SHALL be the provider
name from that list, otherwise the text "Passkey". A blank nickname
SHALL be treated as absent. When that list entry has an icon, the
row SHALL show it. The row SHALL show the registration backup
snapshot as backed up or not backed up, and SHALL show when the
passkey was last used. A missing or legacy backup value SHALL be
shown as unknown and SHALL NOT be shown as "Not backed up". A
missing list entry, or a metadata list that cannot be read, SHALL
still render the row and SHALL NOT fail the page. Assertion and
authorization SHALL NOT accept or reject a ceremony based on the
AAGUID. Registration MAY read the AAGUID only to store it.

#### Scenario: Known authenticator shows its name

- GIVEN a passkey whose AAGUID is in the pinned metadata list and no nickname
- WHEN the account holder opens `GET /account`
- THEN the row shows that list entry's name
- AND it shows the backup flag and last-used time

#### Scenario: Nickname wins

- GIVEN a passkey with a trimmed nonempty nickname and a known AAGUID
- WHEN the account holder opens `GET /account`
- THEN the row's label is the nickname

#### Scenario: Nickname survives a missing list

- GIVEN a passkey with a trimmed nonempty nickname and an AAGUID absent from the list, or a metadata list that cannot be read
- WHEN the account holder opens `GET /account`
- THEN the row's label is the nickname
- AND the rest of the profile is shown

#### Scenario: Blank nickname is absent

- GIVEN a passkey whose nickname is empty or only whitespace and whose AAGUID is known
- WHEN the account holder opens `GET /account`
- THEN the row's label is that list entry's name

#### Scenario: Unknown AAGUID still lists the passkey

- GIVEN a passkey with no nickname whose AAGUID is absent from the list
- WHEN the account holder opens `GET /account`
- THEN the row is labeled "Passkey"
- AND the rest of the profile is shown

#### Scenario: Backup line is the registration snapshot

- GIVEN a passkey stored with the BS bit set or clear
- WHEN the account holder opens `GET /account` after a later assertion
- THEN the row still shows that registration snapshot
- AND a missing backup value is not shown as "Not backed up"

#### Scenario: AAGUID does not decide login

- GIVEN two passkeys for the same account with different stored AAGUIDs
- WHEN either one completes assertion
- THEN the ceremony result does not depend on which AAGUID was stored

## MODIFIED Requirements

### Requirement: First-party signup lands on the account profile
<!-- base: e736cc5d3c131991b09749af8194f3e5b90a617b openspec/specs/passkeys/spec.md -->

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
