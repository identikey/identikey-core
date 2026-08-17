## ADDED Requirements

### Requirement: Threshold pick is provenance, fail-closed on duplicity

Given one or more already-fetched XID document byte-strings, the system
SHALL parse each independently. Unparseable sources SHALL be dropped,
not counted as votes. Among valid documents, the system SHALL take the
highest `bc-xid` provenance mark on a single chain. Two valid documents
that are not on the same provenance chain SHALL fail closed as
duplicity and SHALL NOT produce a winner. Two valid documents with no
provenance marks SHALL succeed only when their bytes are identical;
otherwise they SHALL be duplicity.

#### Scenario: Newer mark on the same chain wins

- GIVEN two valid documents on one provenance chain, B after A
- WHEN `resolve_documents` is called with both
- THEN the result is B

#### Scenario: Divergent valid documents fail closed

- GIVEN two valid documents whose provenance marks are not on the same
  chain
- WHEN `resolve_documents` is called with both
- THEN the result is duplicity and no document is returned

#### Scenario: Unparseable source is not a vote

- GIVEN one valid document and one unparseable byte-string
- WHEN `resolve_documents` is called with both
- THEN the result is the valid document

### Requirement: Consequential operations cannot use cache-only input

`ResolutionTier::Consequential` SHALL refuse input tagged as cached-only.
Ordinary cached resolution MAY accept a single previously fetched
document.

#### Scenario: Consequential rejects cache-only

- GIVEN a single document tagged cached
- WHEN `resolve_documents` is called at the consequential tier
- THEN the call fails and no document is returned

#### Scenario: Cached tier accepts one document

- GIVEN a single valid document tagged cached
- WHEN `resolve_documents` is called at the cached tier
- THEN the result is that document
