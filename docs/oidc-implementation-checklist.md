# OIDC implementation checklist

Cited by `add-pairwise-salt`, `add-sub-seam`, and `add-oidc-endpoints`.
This is the refuse-list. If a grant is not in **Implement**, it is refused.

Sources: RFC 6749/6750, 7636, 8414, 7009, 7662, 9068, OIDC Core + Discovery,
RFC 9700 (Jan 2025, https://www.rfc-editor.org/rfc/rfc9700.html). Device
code (RFC 8628) is implemented for clients that list that grant.

## Implement

| Piece | Spec | Notes |
|---|---|---|
| Authorization code | RFC 6749 §4.1 | `response_type=code` only |
| PKCE `S256` | RFC 7636, RFC 9700 §2.1.1 | Required for every client. `plain` refused |
| Refresh token | RFC 6749 §6, RFC 9700 §2.2.2 | Public clients: rotate on use (`add-refresh-lifecycle`) |
| Device authorization | RFC 8628 | Opt-in per client. The page names the client and the code. A passkey assertion bound to that pending row approves it. User code is not enough |
| Bearer usage | RFC 6750 | Header only. No query-parameter access tokens |
| Discovery | RFC 8414 + OIDC Discovery 1.0 | `/.well-known/openid-configuration` |
| JWKS | OIDC Discovery `jwks_uri` | Signing key only. EdDSA / Ed25519 |
| Revocation | RFC 7009 | `/revoke` |
| Introspection | RFC 7662 | `/introspect` |
| ID Token | OIDC Core | Signed JWT. `sub` from the one seam |
| JWT access tokens | RFC 9068 | Optional; if used, `aud` restricted |

Discovery MUST advertise:

- `response_types_supported`: `["code"]`
- `grant_types_supported`: `["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:identikey:params:oauth:grant-type:challenge-response"]`
- `device_authorization_endpoint`
- `code_challenge_methods_supported`: `["S256"]`
- `subject_types_supported`: `["pairwise", "public"]` (ADR-009)
- `id_token_signing_alg_values_supported`: `["EdDSA"]`
- `token_endpoint_auth_methods_supported`: `["none", "client_secret_basic", "client_secret_post"]`

Discovery MUST NOT advertise `token`, `id_token` as a standalone
response type, or `password`.

## Refuse

Quoted from RFC 9700 unless noted.

| Piece | Rule |
|---|---|
| Resource owner password | **MUST NOT** be used (§2.4) |
| Implicit (`response_type=token`) and other types that issue access tokens in the authorization response | clients **SHOULD NOT**; we do not implement or advertise |
| PKCE missing / `plain` | AS **MUST** support PKCE; we require `S256`. If a challenge was sent, **MUST** enforce verifier. **MUST** reject a verifier when no challenge was stored (§2.1.1) |
| Wildcard / prefix redirect URIs | **MUST** exact string match. Exception: native `localhost` port (RFC 8252 §7.3) (§2.1) |
| `http` redirect URIs | **MUST NOT**, except native loopback (§2.6) |
| CORS on `/authorize` | **MUST NOT** (§2.6) |
| Open redirectors | **MUST NOT** (§2.1) |
| Hybrid (`code id_token`, `code token`) | Not this slice |
| URN grant | Implemented: identikey-auth `Response` only, never a WebAuthn assertion (ADR-005). Opt-in per client, same allow-list as the device grant. Before a wallet client ships, the Response audience must also be the redeeming `client_id`. Today the audience is the issuer. The nonce stops replay. It does not stop cross-client redemption |

## Pairwise KDF (ADR-009 left this open)

**HKDF-SHA-256** (RFC 5869).

```
IKM  = IDENTIKEY_PAIRWISE_SALT   # 32+ bytes, install-generated
salt = sector_identifier         # UTF-8
info = "identikey-oidc-sub-v1" || 0x00 || xid_bytes   # 32-byte XID
L    = 32
sub  = base58btc(HKDF-SHA-256(IKM, salt, info, L))   # same alphabet as public sub; bytes differ
```

`public` subject type: `sub` is the base58btc text form of the 32-byte XID. Never HKDF. Hex is not an identifier form.
Internal keys stay the XID (`identikey-keys`). Pairwise `sub` is
token-boundary only.

## `/health`

Liveness only. No salt, no keys, no “dev login” flag.

## Not in this file

Endpoint code (`ccf.4`), salt install (`88b`), `sub()` (`duw`),
OIDF CI (`ccf.3`), DCR, PAR, DPoP.
