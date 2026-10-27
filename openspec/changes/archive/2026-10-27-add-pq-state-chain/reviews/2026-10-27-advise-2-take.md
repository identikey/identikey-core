1. Pin a versioned, deterministic record encoding that binds the XID, sequence, predecessor, control key, and operational keys under a domain-separated signature.
2. Pin migration as a one-time transition from classical authority into PQ authority for each verifier and XID.
3. Refuse a later classical Elect signature or replacement checkpoint as a way to reset established PQ control.
4. Distinguish the retained bootstrap digest from the advancing accepted head; replay of the anchor cannot roll back the head.
5. Pin predecessor-authorized transitions and possession of the replacement key, with no unsigned authority-bearing fields.
6. Refuse two valid divergent successors without returning either authority, including conflicts discovered after accepting one branch.
7. Pin durable verifier state sufficient to preserve head monotonicity and known duplicity across calls.
8. Keep XID derivation stable and specify the concrete PQ profile and rejection of unsupported versions or suites.
9. Keep caller-supplied chain verification separate from the unchanged well-known document body and the existing URN grant.
10. Accept the tradeoff that local anchoring and fail-closed conflict detection do not prove freshness or reveal a branch never supplied to the verifier.
