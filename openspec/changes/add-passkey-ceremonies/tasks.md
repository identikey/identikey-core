# Tasks

- [ ] Registration: create options + verify attestation via
      `webauthn-rs`; persist passkey credential
- [ ] Assertion: request options + verify; update sign counter
- [ ] Verified assertion can complete `/authorize` with a code
- [ ] Uses `62j` RP ID / origin config; no wildcards
- [ ] Differential tests against `pre-rust-pivot` TS where
      fixtures apply
- [ ] URN grant still refuses a WebAuthn assertion (or is absent)

Not owed here (bullets, not boxes):

- AAGUID display names — `5gh.2`
- Signal APIs — `5gh.3`
- Counter-regression policy — `5gh.4`
- caBLE — `5gh.5`
- Account UI — `ccf.11`
- URN grant implementation — `add-urn-grant`
