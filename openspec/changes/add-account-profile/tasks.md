# Tasks

- [x] Register-finish for hosted signup issues an HttpOnly session cookie and `{ "next": "/account" }`
- [x] `GET /account` renders XID, C2 custody, passkey count; 401 HTML without a cookie
- [x] First-party signup JS follows `next`; OIDC signup still returns to `/authorize/passkey`
- [x] Tests; `clippy -D warnings`
