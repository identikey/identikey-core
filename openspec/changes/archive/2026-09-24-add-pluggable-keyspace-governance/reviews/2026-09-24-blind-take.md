1. Pin an explicit version boundary: existing v1 logs retain roster-admin authorization and their current genesis-hash identity.
2. Pin separate authorization, finality, and secret-release contracts; require evidence that a chosen combination enforces the same accepted state.
3. Pin signed bootstrap and outgoing-policy authorization of handoff, bound to the precise predecessor, successor policy, keyspace, and replay domain.
4. Refuse implicit founder, operator, resolver, or recovery authority after transfer; any recovery must be predeclared and narrowly authorized.
5. Pin deterministic handling of competing transfers and settlement reversals at the last agreed state, including the limits of freezing already released secrets.
6. Pin the collective XID's authenticated binding to keyspace history and its continuity across controller changes without inventing a replacement keyspace identifier.
7. Pin distinct reader membership, collective Sign/Auth, XID control, and delegated agency powers; membership and shared-secret possession must not imply control.
8. Pin Registry instance identity and trust roots independently of Lightning endpoints, including migration, stale views, and equivocation.
9. Refuse core-local wire inventions, premature runtime dispatch, and changes to C2 wrap-target or actor restrictions; protocol-owned contracts and adversarial cases must precede implementation.
10. Tradeoff: prefer a visible loss of governance availability when authority or finality conflicts over an undocumented override, while stating what existing reads and signatures can still do.
