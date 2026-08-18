# Tasks

- [ ] Only SHA-256 hashes of refresh tokens are stored
- [ ] Refresh rotates; previous token is unusable
- [ ] Revoked token rejected at `/token` and `/introspect`
- [ ] Test: revoked token cannot be replayed

Not owed here (bullets, not boxes):

- DPoP / mTLS sender-constrain
- `/token` authorization_code path — `add-oidc-endpoints`
