## ADDED Requirements

### Requirement: Reference reading is recorded and not copied

The repository SHALL keep a reference-reading note at
`docs/oidc/reference-reading.md`. That note SHALL name ory/fosite,
panva/node-oidc-provider, and zitadel/oidc as Apache-2.0 or MIT
works that may be read and SHALL NOT be pasted into this tree. It
SHALL name kanidm as MPL-2.0 and read-only at a distance, with no
checkout in this repository. The note SHALL NOT contain source from
those projects. A later reading SHALL be recordable there as what
was consulted and what was decided, without a code excerpt.

#### Scenario: A note names the set

- GIVEN the reference-reading note
- WHEN someone looks up where to read about an OIDC ambiguity
- THEN fosite, node-oidc-provider, and zitadel/oidc are listed as
  readable and not to be pasted
- AND kanidm is listed as not to be checked out

#### Scenario: No reference source is committed

- GIVEN this repository
- WHEN the tree is searched for a checkout of those projects
- THEN none is present
