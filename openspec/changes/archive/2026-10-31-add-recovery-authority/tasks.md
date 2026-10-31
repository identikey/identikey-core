# Tasks

- [x] Record the recovery matrix: the A1 ceremony is the limited step, and the passkey it enrolls is an ordinary A3 passkey.
- [x] Advise R1 (2026-10-31, astra-arch-review): carry the design's full authority ceiling into the managed-custody delta: A1 proof and the recovery session must not read `managed_key_blob` or grant Elect or Transfer authority (including to an existing key). Add a negative scenario showing the recovery session remains unable to exercise those authorities after passkey enrollment, while a fresh assertion of the ordinary passkey still uses normal C2 consent. See `reviews/2026-10-31-advise.md`.

The email ceremony, the drill, and any product edit wait on activation and on their own nodes. Advise after the human activates. The reader is Astra. Skip Grok.
