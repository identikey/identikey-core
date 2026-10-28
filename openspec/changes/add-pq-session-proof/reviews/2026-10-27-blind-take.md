1. Pin the opening to the verifier's accepted current head, checking both its digest and XID; supplied keys cannot confer authority.
2. Refuse an opening when authority is absent or forked, even if a detached signature checks under a remembered key.
3. Pin whether an established session survives rotation or a detected fork; current-authority proofs must recheck current trust.
4. Pin canonical, versioned, domain-separated opening and MAC transcripts with unambiguous field encodings.
5. Bind the opening to the intended audience and verifier-issued fresh challenge, with explicit ownership of challenge consumption.
6. Bind each MAC to the accepted opening, XID, digest, audience, and actual proved message; resist cross-session substitution.
7. Pin follow-up replay semantics and who owns freshness state; a valid MAC alone does not demonstrate a new action.
8. Refuse a claim of authenticated session establishment unless the shared secret is bound to the signed opening; leaving establishment out of scope must be explicit at the API boundary.
9. Pin failure behavior so rejected inputs neither consume valid sessions nor advance replay state, and require constant-time MAC verification.
10. Tradeoff: symmetric follow-ups save signature cost but every session-key holder can forge them, so they cannot provide transferable attribution or a public proof log.
