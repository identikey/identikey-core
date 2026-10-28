# Tasks

- [ ] Hosted assertion, managed assertion, and the encapsulation verifier share one counter rule
- [ ] A positive counter below the stored value succeeds, is logged, and leaves the stored value
- [ ] Counter 0 succeeds and is not logged as a regression
- [ ] An equal positive counter still fails and leaves the stored value
- [ ] A higher counter still updates the stored value
- [ ] Tests cover the drop, the zero, the equal reject, and the increase on each of the three sites

Out of scope: Signal APIs, a user-visible investigation of the log, and webauthn-rs signature checks.
