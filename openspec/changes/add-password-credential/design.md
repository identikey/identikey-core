# add-password-credential

## Decided

Password stays in this intention, behind the key model, the email
link, and passkey management. It is a credentials kind. It logs in
through authorization-code plus PKCE to the same XID. A0 does not
consent to C2 signing.

## Hasher

`password-hasher` is Argon2id, m=19456 KiB, t=2, p=1, parameters stored in the PHC string. Spike `docs/spikes/password-hasher/finding.md` — go. Do not raise the memory floor in this node.
