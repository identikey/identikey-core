# Tasks

- [x] New crate depends on `openidconnect` 4 and does not modify `identikey-oidc-client`
- [x] Apple: RS256, issuer `https://appleid.apple.com`, required audience, expiry with 5s skew, claims `sub` / `email` / `email_verified` / `is_private_email`
- [x] Google: RS256, issuers `https://accounts.google.com` and `accounts.google.com`, required audience, expiry with 5s skew, claims `sub` / `email` / `email_verified` / `name` / `picture`
- [x] JWKS cache per provider (Apple `https://appleid.apple.com/auth/keys`, Google `https://www.googleapis.com/oauth2/v3/certs`); one refresh on an unknown `kid`; still-missing key fails; a cached `kid` does not refetch
- [x] Reject a non-RS256 token, a wrong issuer, a wrong audience, and an expired token
- [x] Tests cover those cases without a network (pinned JWKS)
- [x] TypeScript verifiers under `web/src/lib/auth/` stay
