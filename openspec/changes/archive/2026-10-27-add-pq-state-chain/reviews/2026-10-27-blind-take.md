1. Pin the original inception-key-derived XID throughout migration and rotation; neither a PQ key fingerprint nor a server account mapping may replace it.
2. Pin canonical, domain-separated record bytes binding XID, sequence, predecessor, control authority, and operational authority together.
3. Require the existing current Elect authority to authorize migration while classical authorization remains trusted, with possession of the proposed PQ control key.
4. After classical authorization leaves policy, refuse first-contact migration without a previously authenticated checkpoint; new PQ possession cannot authenticate the old XID by itself.
5. A retained checkpoint must belong to the verifier’s trust state and be usable away from IdentiKey; a server-served digest cannot establish its own authenticity.
6. Require prior PQ control authority for every successor and new-key possession for replacement; classical operational keys must never reset the chain or its control policy.
7. Distinguish authenticated chain ancestry from freshness: reject rollback and observed forks, and preserve consequential-resolution requirements without treating a sequence as proof of latestness.
8. Preserve the existing URN grant and subject seam: verify.rs returns a classical fingerprint, so this state alone cannot make today’s response authenticate the PQ-bound XID.
9. Keep Sign/Auth separate from Elect-like control, and do not quietly enable successor pre-commitment without ADR-008’s custody separation and recovery conditions.
10. Tradeoff: portable verifier checkpoints and fail-closed cold starts sacrifice immediate onboarding and recovery availability to avoid silently granting post-cutoff control to classical forgeries.
