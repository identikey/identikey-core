#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use identikey_social_id::{JwksSource, Provider, SocialIdVerifier, SocialIdentity, VerifyError};
use josekit::{
    jws::{JwsHeader, RS256, RS384},
    jwt::{self, JwtPayload},
};
use openidconnect::core::CoreJsonWebKeySet;
use serde_json::{Value, json};

const NOW: i64 = 1_800_000_000;
const AUDIENCE: &str = "caller-client-id";
const KEY: &[u8] = include_bytes!("fixtures/test-only-rsa.pem");
const JWKS: &str = include_str!("fixtures/jwks.json");

fn keys() -> CoreJsonWebKeySet {
    serde_json::from_str(JWKS).unwrap()
}

// No HTTP server or network. The immutable fixture is the only key source.
#[derive(Clone)]
struct Source {
    apple_fetches: Arc<AtomicUsize>,
    google_fetches: Arc<AtomicUsize>,
    document: &'static str,
    fail: bool,
}
impl Source {
    fn new() -> Self {
        Self {
            apple_fetches: Arc::new(AtomicUsize::new(0)),
            google_fetches: Arc::new(AtomicUsize::new(0)),
            document: JWKS,
            fail: false,
        }
    }
    fn count(&self, provider: Provider) -> usize {
        match provider {
            Provider::Apple => &self.apple_fetches,
            Provider::Google => &self.google_fetches,
        }
        .load(Ordering::SeqCst)
    }
}
impl JwksSource for Source {
    async fn fetch(&self, provider: Provider) -> Result<CoreJsonWebKeySet, VerifyError> {
        match provider {
            Provider::Apple => &self.apple_fetches,
            Provider::Google => &self.google_fetches,
        }
        .fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(VerifyError::Jwks("injected fetch failure".into()));
        }
        Ok(serde_json::from_str(self.document).unwrap())
    }
}

fn claims(provider: Provider) -> Value {
    json!({"iss": match provider {Provider::Apple => "https://appleid.apple.com", Provider::Google => "https://accounts.google.com"},
        "aud": AUDIENCE, "sub": "provider-subject", "exp": NOW + 300,
        "email": "person@example.com", "email_verified": true})
}
fn mint(claims: Value, kid: Option<&str>, alg: &str) -> String {
    let payload = JwtPayload::from_map(claims.as_object().unwrap().clone()).unwrap();
    let mut header = JwsHeader::new();
    header.set_algorithm(alg);
    if let Some(kid) = kid {
        header.set_key_id(kid);
    }
    match alg {
        "RS256" => jwt::encode_with_signer(&payload, &header, &RS256.signer_from_pem(KEY).unwrap())
            .unwrap(),
        "RS384" => jwt::encode_with_signer(&payload, &header, &RS384.signer_from_pem(KEY).unwrap())
            .unwrap(),
        _ => unreachable!(),
    }
}
fn token(claims: Value) -> String {
    mint(claims, Some("pinned-rsa"), "RS256")
}
fn verifier(source: Source) -> SocialIdVerifier<Source> {
    SocialIdVerifier::with_cached_jwks(source, keys(), keys())
}

#[tokio::test]
async fn apple_returns_profile_and_normalizes_boolean_strings() {
    let source = Source::new();
    let verifier = verifier(source.clone());
    let mut claims = claims(Provider::Apple);
    claims["email_verified"] = json!("true");
    claims["is_private_email"] = json!("false");
    let SocialIdentity::Apple(identity) = verifier
        .verify(Provider::Apple, &token(claims), AUDIENCE, NOW)
        .await
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(identity.sub, "provider-subject");
    assert_eq!(identity.email.as_deref(), Some("person@example.com"));
    assert_eq!(identity.email_verified, Some(true));
    assert_eq!(identity.is_private_email, Some(false));
    assert_eq!(source.count(Provider::Apple), 0);
}

#[tokio::test]
async fn optional_profile_claims_may_be_absent() {
    for provider in [Provider::Apple, Provider::Google] {
        let mut claims = claims(provider);
        claims.as_object_mut().unwrap().remove("email");
        claims.as_object_mut().unwrap().remove("email_verified");
        let identity = verifier(Source::new())
            .verify(provider, &token(claims), AUDIENCE, NOW)
            .await
            .unwrap();
        let serialized = match identity {
            SocialIdentity::Apple(id) => {
                assert_eq!(id.is_private_email, None);
                serde_json::to_value(id).unwrap()
            }
            SocialIdentity::Google(id) => {
                assert_eq!((id.name.clone(), id.picture.clone()), (None, None));
                serde_json::to_value(id).unwrap()
            }
        };
        assert_eq!(serialized, json!({"sub":"provider-subject"}));
    }
}

#[tokio::test]
async fn google_accepts_both_exact_issuers_and_returns_profile() {
    let verifier = verifier(Source::new());
    for issuer in ["https://accounts.google.com", "accounts.google.com"] {
        let mut claims = claims(Provider::Google);
        claims["iss"] = json!(issuer);
        claims["name"] = json!("A Person");
        claims["picture"] = json!("https://example.com/avatar.png");
        let SocialIdentity::Google(id) = verifier
            .verify(Provider::Google, &token(claims), AUDIENCE, NOW)
            .await
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(id.sub, "provider-subject");
        assert_eq!(id.email.as_deref(), Some("person@example.com"));
        assert_eq!(id.email_verified, Some(true));
        assert_eq!(id.name.as_deref(), Some("A Person"));
        assert_eq!(
            id.picture.as_deref(),
            Some("https://example.com/avatar.png")
        );
    }
}

#[tokio::test]
async fn rejects_wrong_issuer_audience_and_expired_for_each_provider() {
    let verifier = verifier(Source::new());
    for provider in [Provider::Apple, Provider::Google] {
        for issuer in [
            "https://evil.example",
            "https://accounts.google.com/",
            "https://appleid.apple.com/",
        ] {
            let mut claims = claims(provider);
            claims["iss"] = json!(issuer);
            assert!(matches!(
                verifier
                    .verify(provider, &token(claims), AUDIENCE, NOW)
                    .await,
                Err(VerifyError::BadIssuer)
            ));
        }
        let mut wrong_aud = claims(provider);
        wrong_aud["aud"] = json!("another-client");
        assert!(matches!(
            verifier
                .verify(provider, &token(wrong_aud), AUDIENCE, NOW)
                .await,
            Err(VerifyError::BadAudience)
        ));
        let mut expired = claims(provider);
        expired["exp"] = json!(NOW - 6);
        assert!(matches!(
            verifier
                .verify(provider, &token(expired), AUDIENCE, NOW)
                .await,
            Err(VerifyError::Expired)
        ));
        assert!(matches!(
            verifier
                .verify(provider, &token(claims(provider)), "", NOW)
                .await,
            Err(VerifyError::BadAudience)
        ));
    }
}

#[tokio::test]
async fn expiry_skew_boundary_is_five_seconds() {
    for provider in [Provider::Apple, Provider::Google] {
        let verifier = verifier(Source::new());
        for (expiry, valid) in [
            (NOW + 1, true),
            (NOW, true),
            (NOW - 4, true),
            (NOW - 5, false),
            (NOW - 6, false),
        ] {
            let mut claims = claims(provider);
            claims["exp"] = json!(expiry);
            assert_eq!(
                verifier
                    .verify(provider, &token(claims), AUDIENCE, NOW)
                    .await
                    .is_ok(),
                valid
            );
        }
    }
}

#[tokio::test]
async fn rejects_other_algorithms_and_missing_kid_without_fetching() {
    for provider in [Provider::Apple, Provider::Google] {
        let source = Source::new();
        let verifier = SocialIdVerifier::with_source(source.clone());
        let signed_rs384 = mint(claims(provider), Some("pinned-rsa"), "RS384");
        assert!(matches!(
            verifier
                .verify(provider, &signed_rs384, AUDIENCE, NOW)
                .await,
            Err(VerifyError::UnsupportedAlgorithm)
        ));
        for alg in ["none", "HS256", "EdDSA"] {
            let header = URL_SAFE_NO_PAD.encode(json!({"alg":alg,"kid":"pinned-rsa"}).to_string());
            let payload = URL_SAFE_NO_PAD.encode(claims(provider).to_string());
            assert!(matches!(
                verifier
                    .verify(provider, &format!("{header}.{payload}."), AUDIENCE, NOW)
                    .await,
                Err(VerifyError::UnsupportedAlgorithm)
            ));
        }
        assert!(matches!(
            verifier
                .verify(
                    provider,
                    &mint(claims(provider), None, "RS256"),
                    AUDIENCE,
                    NOW
                )
                .await,
            Err(VerifyError::MissingKeyId)
        ));
        assert_eq!(source.count(provider), 0);
    }
}

#[tokio::test]
async fn unknown_kid_refreshes_once_then_uses_cache_per_provider() {
    let source = Source::new();
    let verifier = SocialIdVerifier::with_source(source.clone());
    for provider in [Provider::Apple, Provider::Google] {
        let token = token(claims(provider));
        for _ in 0..3 {
            verifier
                .verify(provider, &token, AUDIENCE, NOW)
                .await
                .unwrap();
        }
        assert_eq!(source.count(provider), 1);
        if provider == Provider::Apple {
            assert_eq!(source.count(Provider::Google), 0);
        }
    }
}

#[tokio::test]
async fn refresh_replaces_cache_and_still_missing_key_fails() {
    for provider in [Provider::Apple, Provider::Google] {
        let mut source = Source::new();
        source.document = "{\"keys\":[]}";
        let verifier = verifier(source.clone());
        let missing = mint(claims(provider), Some("rotated-key"), "RS256");
        assert!(matches!(
            verifier.verify(provider, &missing, AUDIENCE, NOW).await,
            Err(VerifyError::NoKey)
        ));
        assert_eq!(source.count(provider), 1);
        // Replacement removed the old cached key, so it must fetch again.
        assert!(matches!(
            verifier
                .verify(provider, &token(claims(provider)), AUDIENCE, NOW)
                .await,
            Err(VerifyError::NoKey)
        ));
        assert_eq!(source.count(provider), 2);
    }
}

#[tokio::test]
async fn fetch_failure_fails_closed_and_preserves_cached_keys() {
    let mut source = Source::new();
    source.fail = true;
    let verifier = verifier(source.clone());
    for provider in [Provider::Apple, Provider::Google] {
        let missing = mint(claims(provider), Some("unknown"), "RS256");
        assert!(matches!(
            verifier.verify(provider, &missing, AUDIENCE, NOW).await,
            Err(VerifyError::Jwks(_))
        ));
        verifier
            .verify(provider, &token(claims(provider)), AUDIENCE, NOW)
            .await
            .unwrap();
        assert_eq!(source.count(provider), 1);
    }
}

#[tokio::test]
async fn bad_signature_with_cached_kid_does_not_refetch() {
    let source = Source::new();
    let verifier = verifier(source.clone());
    for provider in [Provider::Apple, Provider::Google] {
        let good = token(claims(provider));
        let (signed, _) = good.rsplit_once('.').unwrap();
        let corrupted = format!("{signed}.{}", URL_SAFE_NO_PAD.encode([0u8; 256]));
        assert!(matches!(
            verifier.verify(provider, &corrupted, AUDIENCE, NOW).await,
            Err(VerifyError::BadSignature)
        ));
        assert_eq!(source.count(provider), 0);
    }
}

#[tokio::test]
async fn required_claims_and_boolean_types_are_validated() {
    let verifier = verifier(Source::new());
    for provider in [Provider::Apple, Provider::Google] {
        for field in ["iss", "aud", "exp", "sub"] {
            let mut claims = claims(provider);
            claims.as_object_mut().unwrap().remove(field);
            assert!(matches!(
                verifier
                    .verify(provider, &token(claims), AUDIENCE, NOW)
                    .await,
                Err(VerifyError::Malformed(_))
            ));
        }
        let mut no_sub = claims(provider);
        no_sub["sub"] = json!("");
        assert!(matches!(
            verifier
                .verify(provider, &token(no_sub), AUDIENCE, NOW)
                .await,
            Err(VerifyError::NoSubject)
        ));
        let mut bad_bool = claims(provider);
        bad_bool["email_verified"] = json!("not-a-boolean");
        assert!(matches!(
            verifier
                .verify(provider, &token(bad_bool), AUDIENCE, NOW)
                .await,
            Err(VerifyError::Malformed(_))
        ));
        let mut auds = claims(provider);
        auds["aud"] = json!(["another-client", AUDIENCE]);
        verifier
            .verify(provider, &token(auds), AUDIENCE, NOW)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn malformed_tokens_fail_without_fetch() {
    let source = Source::new();
    let verifier = SocialIdVerifier::with_source(source.clone());
    for token in ["", "abc", "a.b", "a.b.c", "a.b.c.d"] {
        assert!(
            verifier
                .verify(Provider::Apple, token, AUDIENCE, NOW)
                .await
                .is_err()
        );
    }
    assert_eq!(source.count(Provider::Apple), 0);
}

#[tokio::test]
async fn concurrent_cache_misses_share_successful_refresh() {
    let source = Source::new();
    let verifier = SocialIdVerifier::with_source(source.clone());
    let token = token(claims(Provider::Apple));
    let (a, b) = tokio::join!(
        verifier.verify(Provider::Apple, &token, AUDIENCE, NOW),
        verifier.verify(Provider::Apple, &token, AUDIENCE, NOW)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(source.count(Provider::Apple), 1);
}

#[test]
fn jwks_endpoints_are_pinned() {
    assert_eq!(
        Provider::Apple.jwks_url(),
        "https://appleid.apple.com/auth/keys"
    );
    assert_eq!(
        Provider::Google.jwks_url(),
        "https://www.googleapis.com/oauth2/v3/certs"
    );
}
