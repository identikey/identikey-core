use identikey_oidc::{Client, KNOWN_GRANTS, SubjectType, TokenEndpointAuthMethod};
use serde::Deserialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Deserialize)]
struct ClientJson {
    id: String,
    #[serde(default)]
    redirect: Option<String>,
    #[serde(default)]
    redirects: Vec<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    subject_type: Option<String>,
    #[serde(default)]
    sector: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    grants: Option<Vec<String>>,
}

#[derive(Clone, Copy)]
enum Source {
    Primary,
    Json,
}

impl Source {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Json => "json",
        }
    }
}

struct Registration {
    client: Client,
    source: Source,
    pin: Option<String>,
    legacy: String,
}

struct ClientSpec {
    id: String,
    redirects: Vec<String>,
    secret: Option<String>,
    auth: Option<String>,
    subject_type: Option<String>,
    sector: Option<String>,
    name: Option<String>,
    grants: Option<Vec<String>>,
}

impl ClientSpec {
    fn into_client(self) -> Result<Client, BoxError> {
        client_from_parts(
            self.id,
            self.redirects,
            self.secret,
            self.auth,
            self.subject_type,
            self.sector,
            self.name,
            self.grants,
        )
    }

    fn into_registration(self, source: Source) -> Result<Registration, BoxError> {
        let legacy = legacy_sector(&self.redirects);
        let pin = self.sector.clone();
        let client = self.into_client()?;
        Ok(Registration {
            client,
            source,
            pin,
            legacy,
        })
    }
}

#[cfg(test)]
pub(crate) fn client_from_spec(
    id: String,
    redirects: Vec<String>,
    secret: Option<String>,
    auth: Option<String>,
    subject_type: Option<String>,
    sector: Option<String>,
) -> Result<Client, BoxError> {
    client_from_parts(
        id,
        redirects,
        secret,
        auth,
        subject_type,
        sector,
        None,
        None,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "registration fields stay positional so the JSON loader and the tests name the same inputs"
)]
fn client_from_parts(
    id: String,
    redirects: Vec<String>,
    secret: Option<String>,
    auth: Option<String>,
    subject_type: Option<String>,
    sector: Option<String>,
    name: Option<String>,
    grants: Option<Vec<String>>,
) -> Result<Client, BoxError> {
    let grants = match grants {
        Some(grants) => {
            for grant in &grants {
                if !KNOWN_GRANTS.contains(&grant.as_str()) {
                    return Err(format!("unknown OIDC grant_type {grant}").into());
                }
            }
            Some(grants)
        }
        None => None,
    };
    let needs_redirect = grants.as_ref().is_none_or(|grants| {
        grants
            .iter()
            .any(|grant| grant == identikey_oidc::GRANT_AUTHORIZATION_CODE)
    });
    if id.is_empty()
        || redirects.iter().any(String::is_empty)
        || (needs_redirect && redirects.is_empty())
    {
        return Err("OIDC client id and redirect are required".into());
    }
    let method = match (auth.as_deref(), secret.as_deref()) {
        (Some(raw), _) => TokenEndpointAuthMethod::parse(raw).map_err(|e| e.to_string())?,
        (None, Some(s)) if !s.is_empty() => TokenEndpointAuthMethod::ClientSecretBasic,
        (None, _) => TokenEndpointAuthMethod::None,
    };
    let subject_type = match subject_type.as_deref().filter(|value| !value.is_empty()) {
        Some(raw) => SubjectType::parse(raw)?,
        None => SubjectType::Pairwise,
    };
    let sector = match (subject_type, sector) {
        (SubjectType::Pairwise, Some(sector)) if !sector.is_empty() => sector,
        (SubjectType::Pairwise, _) => {
            return Err(format!("pairwise OIDC client {id} requires a non-empty sector").into());
        }
        (SubjectType::Public, Some(sector)) if !sector.is_empty() => sector,
        (SubjectType::Public, _) => id.clone(),
    };

    let mut client = Client::new(id.as_str(), sector).with_subject_type(subject_type);
    if let Some(grants) = grants {
        client = client.with_grants(grants);
    }
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        client = client.with_display_name(name);
    }
    for redirect in redirects {
        client = client.with_redirect(redirect);
    }
    match (method, secret.as_deref().filter(|s| !s.is_empty())) {
        (TokenEndpointAuthMethod::None, Some(_)) => {
            Err("public client (token_endpoint_auth_method=none) must not have a secret".into())
        }
        (TokenEndpointAuthMethod::None, None) => Ok(client),
        (confidential, Some(secret)) => Ok(client.with_secret(confidential, secret)),
        (confidential, None) => Err(format!(
            "confidential client {} requires a secret",
            confidential.as_str()
        )
        .into()),
    }
}

fn merge_redirects(primary: Option<String>, extra: Vec<String>) -> Vec<String> {
    let mut redirects = Vec::new();
    if let Some(primary) = primary.filter(|s| !s.is_empty()) {
        redirects.push(primary);
    }
    for uri in extra {
        if !uri.is_empty() && !redirects.contains(&uri) {
            redirects.push(uri);
        }
    }
    redirects
}

/// Reproduce the sector selected by the pre-pin loader. This is migration-only:
/// boot and request handling construct clients exclusively through configured pins.
fn legacy_sector(redirects: &[String]) -> String {
    redirects
        .first()
        .and_then(|redirect| url::Url::parse(redirect).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "default".into())
}

fn primary_spec(
    id: Option<String>,
    redirect: Option<String>,
    secret: Option<String>,
    auth: Option<String>,
    subject_type: Option<String>,
    sector: Option<String>,
) -> Option<ClientSpec> {
    let id = id.filter(|id| !id.is_empty())?;
    Some(ClientSpec {
        id,
        redirects: merge_redirects(redirect, Vec::new()),
        secret,
        auth,
        subject_type,
        sector,
        name: None,
        grants: None,
    })
}

fn primary_spec_from_env() -> Option<ClientSpec> {
    primary_spec(
        std::env::var("IDENTIKEY_CLIENT_ID").ok(),
        Some(std::env::var("IDENTIKEY_CLIENT_REDIRECT").unwrap_or_default()),
        std::env::var("IDENTIKEY_CLIENT_SECRET").ok(),
        std::env::var("IDENTIKEY_CLIENT_AUTH_METHOD").ok(),
        std::env::var("IDENTIKEY_CLIENT_SUBJECT_TYPE").ok(),
        std::env::var("IDENTIKEY_CLIENT_SECTOR").ok(),
    )
}

fn specs_from_json(raw: Option<&str>) -> Result<Vec<ClientSpec>, BoxError> {
    let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
        return Ok(Vec::new());
    };
    let specs: Vec<ClientJson> = serde_json::from_str(raw)
        .map_err(|e| format!("IDENTIKEY_CLIENTS is not valid JSON: {e}"))?;
    Ok(specs
        .into_iter()
        .map(|spec| ClientSpec {
            id: spec.id,
            redirects: merge_redirects(spec.redirect, spec.redirects),
            secret: spec.secret,
            auth: spec.auth,
            subject_type: spec.subject_type,
            sector: spec.sector,
            name: spec.name,
            grants: spec.grants,
        })
        .collect())
}

fn registrations_from_json(raw: Option<&str>) -> Result<Vec<Registration>, BoxError> {
    specs_from_json(raw)?
        .into_iter()
        .map(|spec| spec.into_registration(Source::Json))
        .collect()
}

fn extra_registrations() -> Result<Vec<Registration>, BoxError> {
    registrations_from_json(std::env::var("IDENTIKEY_CLIENTS").ok().as_deref())
}

pub(crate) fn optional_client() -> Result<Option<Client>, BoxError> {
    primary_spec_from_env()
        .map(ClientSpec::into_client)
        .transpose()
}

pub(crate) fn extra_clients() -> Result<Vec<Client>, BoxError> {
    specs_from_json(std::env::var("IDENTIKEY_CLIENTS").ok().as_deref())?
        .into_iter()
        .map(ClientSpec::into_client)
        .collect()
}

fn report(registrations: &[Registration]) -> Result<(String, bool), BoxError> {
    let mut output = String::new();
    let mut all_match = true;
    for registration in registrations {
        let pairwise = registration.client.subject_type == SubjectType::Pairwise;
        let matches = if !pairwise {
            true
        } else if registration.client.redirect_uris.is_empty() {
            registration
                .pin
                .as_deref()
                .is_some_and(|pin| !pin.is_empty())
        } else {
            registration.pin.as_deref() == Some(registration.legacy.as_str())
        };
        all_match &= matches;
        let id = serde_json::to_string(&registration.client.id)?;
        let pin = serde_json::to_string(&registration.pin)?;
        let legacy = serde_json::to_string(&registration.legacy)?;
        output.push_str(&format!(
            "id={id} source={} subject_type={} pin={pin} legacy={legacy} match={matches}\n",
            registration.source.as_str(),
            registration.client.subject_type.as_str(),
        ));
    }
    Ok((output, all_match))
}

/// Compare configured pins with the exact sector the previous loader selected.
/// This command intentionally loads no salt, key, database, or network resource.
pub(crate) fn check_clients() -> Result<bool, BoxError> {
    let mut registrations = Vec::new();
    if let Some(primary) = primary_spec_from_env() {
        registrations.push(primary.into_registration(Source::Primary)?);
    }
    registrations.extend(extra_registrations()?);
    let (output, all_match) = report(&registrations)?;
    print!("{output}");
    Ok(all_match)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use identikey_keys::Xid;
    use identikey_oidc::{PairwiseSalt, subject};

    fn salt() -> PairwiseSalt {
        PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn xid() -> Xid {
        Xid::from_bytes([0x11; 32])
    }

    fn assert_legacy_subject(registration: &Registration) {
        let legacy = Client::new(&registration.client.id, &registration.legacy);
        assert_eq!(
            subject(&salt(), xid(), &registration.client).unwrap(),
            subject(&salt(), xid(), &legacy).unwrap()
        );
    }

    #[test]
    fn primary_omitted_pairwise_pin_preserves_legacy_subject_verbatim() {
        let registration = primary_spec(
            Some("taskmaster".into()),
            Some("https://TASKMASTER.dev/auth/callback".into()),
            Some("secret".into()),
            Some("client_secret_basic".into()),
            None,
            Some("taskmaster.dev".into()),
        )
        .unwrap()
        .into_registration(Source::Primary)
        .unwrap();
        assert_eq!(registration.legacy, "taskmaster.dev");
        assert_legacy_subject(&registration);

        let opaque = client_from_spec(
            "opaque".into(),
            vec!["https://elsewhere.example/cb".into()],
            None,
            None,
            None,
            Some(" MiXeD.Example/Path ".into()),
        )
        .unwrap();
        assert_eq!(opaque.sector_identifier, " MiXeD.Example/Path ");
    }

    #[test]
    fn json_explicit_pairwise_uses_singular_redirect_precedence() {
        let registrations = registrations_from_json(Some(
            r#"[{"id":"client","redirect":"https://FIRST.Example/cb","redirects":["https://second.example/cb","https://FIRST.Example/cb"],"subject_type":"pairwise","sector":"first.example"}]"#,
        ))
        .unwrap();
        assert_eq!(registrations[0].client.redirect_uris.len(), 2);
        assert_eq!(registrations[0].legacy, "first.example");
        assert_legacy_subject(&registrations[0]);
    }

    #[test]
    fn pairwise_missing_or_empty_pin_names_primary_and_json_clients() {
        for sector in [None, Some(String::new())] {
            let error = primary_spec(
                Some("primary-pairwise".into()),
                Some("https://primary.example/cb".into()),
                None,
                None,
                None,
                sector,
            )
            .unwrap()
            .into_client()
            .err()
            .unwrap()
            .to_string();
            assert!(error.contains("primary-pairwise"));
        }

        for raw in [
            r#"[{"id":"json-missing","redirect":"https://json.example/cb"}]"#,
            r#"[{"id":"json-empty","redirect":"https://json.example/cb","sector":""}]"#,
        ] {
            let error = registrations_from_json(Some(raw))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("json-"));
        }
    }

    #[test]
    fn public_client_needs_no_sector_and_subject_is_xid() {
        let client = client_from_spec(
            "public-client".into(),
            vec!["https://public.example/cb".into()],
            None,
            Some("none".into()),
            Some("public".into()),
            None,
        )
        .unwrap();
        assert_eq!(subject(&salt(), xid(), &client).unwrap(), xid().to_string());
    }

    #[test]
    fn legacy_sector_uses_default_for_hostless_and_unparseable_redirects() {
        for redirect in ["mailto:user@example.com", "not a URL"] {
            let redirects = vec![redirect.to_owned()];
            assert_eq!(legacy_sector(&redirects), "default");
            let client = client_from_spec(
                redirect.into(),
                redirects,
                None,
                None,
                None,
                Some("default".into()),
            )
            .unwrap();
            let legacy = Client::new(&client.id, "default");
            assert_eq!(
                subject(&salt(), xid(), &client).unwrap(),
                subject(&salt(), xid(), &legacy).unwrap()
            );
        }
    }

    #[test]
    fn redirect_mutations_do_not_change_pinned_subject() {
        let variants = [
            vec!["https://taskmaster.dev/auth/callback"],
            vec![
                "https://new.example/cb",
                "https://taskmaster.dev/auth/callback",
            ],
            vec![
                "https://taskmaster.dev/auth/callback",
                "https://new.example/cb",
            ],
            vec!["https://replacement.example/cb"],
            vec!["https://remaining.example/cb"],
        ];
        let expected = variants
            .iter()
            .map(|redirects| {
                let client = client_from_spec(
                    "taskmaster".into(),
                    redirects
                        .iter()
                        .map(|redirect| (*redirect).into())
                        .collect(),
                    None,
                    None,
                    None,
                    Some("taskmaster.dev".into()),
                )
                .unwrap();
                subject(&salt(), xid(), &client).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(expected.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn sanitized_pairwise_fixtures_match_legacy_subjects() {
        let raw = r#"[
            {"id":"taskmaster","redirect":"https://taskmaster.dev/auth/callback","sector":"taskmaster.dev"},
            {"id":"taskmaster-laptop","redirect":"http://127.0.0.1:5173/auth/callback","sector":"127.0.0.1"},
            {"id":"localhost","redirect":"http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback","redirects":["http://localhost:8008/_matrix/client/v3/login/identikey/callback"],"secret":"sanitized","auth":"client_secret_basic","sector":"127.0.0.1"},
            {"id":"wtnf-web","redirect":"https://worldtree.network/admin/callback/","redirects":["http://127.0.0.1:5173/admin/callback/"],"auth":"none","sector":"worldtree.network"}
        ]"#;
        let registrations = registrations_from_json(Some(raw)).unwrap();
        assert_eq!(registrations.len(), 4);
        for registration in &registrations {
            assert_legacy_subject(registration);
        }
    }

    #[test]
    fn report_has_required_fields_flags_mismatch_and_never_prints_secret() {
        let registrations = registrations_from_json(Some(
            r#"[
                {"id":"mismatch","redirect":"https://taskmaster.dev/auth/callback","sector":"www.taskmaster.dev","secret":"never-print-me","auth":"client_secret_basic"},
                {"id":"public","redirect":"https://public.example/cb","subject_type":"public"}
            ]"#,
        ))
        .unwrap();
        let (output, all_match) = report(&registrations).unwrap();
        assert!(!all_match);
        assert!(output.contains("id=\"mismatch\" source=json subject_type=pairwise"));
        assert!(output.contains("pin=\"www.taskmaster.dev\""));
        assert!(output.contains("legacy=\"taskmaster.dev\" match=false"));
        assert!(output.contains("id=\"public\" source=json subject_type=public pin=null"));
        assert!(!output.contains("never-print-me"));
    }

    #[test]
    fn device_only_registration_omits_redirect_and_keeps_an_explicit_pin() {
        let registrations = registrations_from_json(Some(
            r#"[{"id":"cli","name":"Mjolnir CLI","subject_type":"public","grants":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}]"#,
        ))
        .unwrap();
        assert!(registrations[0].client.redirect_uris.is_empty());
        assert_eq!(registrations[0].client.display_name, "Mjolnir CLI");
        assert!(
            registrations[0]
                .client
                .allows_grant(identikey_oidc::GRANT_DEVICE_CODE)
        );
        assert!(
            !registrations[0]
                .client
                .allows_grant(identikey_oidc::GRANT_AUTHORIZATION_CODE)
        );
        let (output, all_match) = report(&registrations).unwrap();
        assert!(all_match, "{output}");

        let pairwise = registrations_from_json(Some(
            r#"[{"id":"pair-cli","subject_type":"pairwise","sector":"tools.example","grants":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}]"#,
        ))
        .unwrap();
        let (output, all_match) = report(&pairwise).unwrap();
        assert!(all_match, "{output}");
        assert_eq!(pairwise[0].legacy, "default");

        let error = registrations_from_json(Some(
            r#"[{"id":"bad","redirect":"https://example.invalid/cb","sector":"example.invalid","grants":["implicit"]}]"#,
        ))
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("unknown OIDC grant_type"));
    }
}
