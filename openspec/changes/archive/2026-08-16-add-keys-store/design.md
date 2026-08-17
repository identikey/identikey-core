# Design — add-keys-store

## Elect is checked against the row, not the caller

`bc-xid` will mutate any in-memory `XIDDocument`. The store loads
`custody_records.xid_document` (`SELECT … FOR UPDATE`), parses it, calls
`authorize_elect`, and only then writes the new bytes. A caller who
passes a forged "previous" document cannot skip the gate.

## Documents are public

Stored CBOR is the unsigned XID document with private keys omitted
(`XIDPrivateKeyOptions::Omit` / the tagged-CBOR encoding that does not
carry `PrivateKeys`). `managed_key_blob` is a separate column and stays
opaque. Encryption of that blob is not this change.

## Boot

No `DATABASE_URL` → process exits. An auth server that is up without a
store is a lie. `/health` does not report on the pool.
