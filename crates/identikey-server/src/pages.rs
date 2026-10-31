//! Hosted HTML for passkey login and signup (`add-hosted-login-ui`).
//!
//! Kept out of `main.rs` so the product pages are not a `format!` of
//! inline HTML mixed with route wiring.

/// Escape text for HTML element or attribute content.
#[must_use]
pub fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// JSON embedded in `<script type="application/json">` must not contain `</`.
#[must_use]
pub fn json_for_script(raw: &str) -> String {
    raw.replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

// The hosted pages' styles and scripts live beside this file so they can be
// linted and read as CSS/JS; they are embedded, so the binary is self-contained.
const PAGES_CSS: &str = include_str!("pages.css");
const COMMON_JS: &str = include_str!("pages-common.js");
const LOGIN_JS: &str = include_str!("pages-login.js");
const SIGNUP_JS: &str = include_str!("pages-signup.js");
const DEVICE_JS: &str = include_str!("pages-device.js");

fn shell(title: &str, inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/>\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>\
         <title>{}</title><style>{PAGES_CSS}</style></head>\
         <body><main><div class=\"brand\">IdentiKey</div>{}</main></body></html>",
        html_escape(title),
        inner
    )
}

/// Shown only on loopback hosts (by `pages-common.js`), so a local account is
/// never mistaken for one on the live service.
const LOCAL_NOTICE: &str = "<p id=\"local-notice\" class=\"local\" hidden>\
     Local development server. Accounts here are separate from your live IdentiKey account.</p>";

/// Feedback panel filled by `status()` in `pages-common.js`. It takes focus
/// and is announced, so keyboard and screen-reader users hear the outcome.
const STATUS_PANEL: &str = "<div id=\"status\" class=\"status\" role=\"status\" \
     aria-live=\"polite\" tabindex=\"-1\" hidden>\
     <h2 id=\"status-title\"></h2><p id=\"status-description\"></p>\
     <button type=\"button\" id=\"copy-report\" hidden>Copy diagnostics</button>\
     <p id=\"copy-result\" role=\"status\"></p></div>";

/// Collapsed API error for developers: code, description and HTTP status,
/// written with `textContent`, never as HTML.
const TECHNICAL_DETAILS: &str = "<details id=\"technical\" hidden>\
     <summary>Technical details</summary><pre id=\"technical-message\"></pre></details>";

/// Production assertion page for `GET /authorize/passkey`.
#[must_use]
pub fn passkey_login(ceremony_json: &str, used_here: &[String]) -> String {
    let json = json_for_script(ceremony_json);
    let remembered = device_passkey_line(used_here);
    shell(
        "Sign in — IdentiKey",
        &format!(
            "{LOCAL_NOTICE}\
             <h1>Sign in</h1>\
             <p>Use a passkey from 1Password, iCloud Keychain, or this device. No username.</p>\
             {remembered}\
             {STATUS_PANEL}\
             <button type=\"button\" id=\"go\">Continue with passkey</button>\
             <div class=\"secondary-path\">\
             <h2>New to IdentiKey?</h2>\
             <p>Creating an account makes a new identity. It does not recover an existing one.</p>\
             <a id=\"signup\" class=\"action\" href=\"/signup\">Create an account</a>\
             </div>\
             <details id=\"passkey-help\">\
             <summary>Passkey not showing up?</summary>\
             <ul>\
             <li>In the browser prompt, choose where your passkey is saved: another password \
             manager, a security key, or a phone or tablet nearby.</li>\
             <li>A passkey saved on your phone works here too: pick the phone option in the \
             prompt and scan the code it shows.</li>\
             <li>A passkey belongs to the site it was made for. One made for another site or app \
             will not appear here.</li>\
             </ul>\
             </details>\
             {TECHNICAL_DETAILS}\
             <script type=\"application/json\" id=\"ceremony\">{json}</script>\
             <script>{COMMON_JS}\n{LOGIN_JS}</script>"
        ),
    )
}

/// Names of passkeys this browser has already used. Empty when there are none.
fn device_passkey_line(labels: &[String]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let rendered = match labels {
        [one] => html_escape(one),
        [first, second] => format!("{} and {}", html_escape(first), html_escape(second)),
        many => {
            let Some((last, head)) = many.split_last() else {
                return String::new();
            };
            let head = head
                .iter()
                .map(|label| html_escape(label))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{head}, and {}", html_escape(last))
        }
    };
    format!("<p class=\"device-passkeys\">This browser has used {rendered}.</p>")
}

/// `GET /signup` — creates nothing until POST.
#[must_use]
pub fn signup() -> String {
    shell(
        "Create account — IdentiKey",
        &format!(
            "{LOCAL_NOTICE}\
             <h1>Create an account</h1>\
             <p>We will create a managed identity and enroll a passkey. Save it in \
             1Password (or iCloud Keychain / this device) when the browser asks. \
             This is access, not your Elect key.</p>\
             <p>This makes a new account. If you already have one, go back and sign in \
             with its passkey instead; a new account will not restore it.</p>\
             {STATUS_PANEL}\
             <button type=\"button\" id=\"go\">Create account and add a passkey</button>\
             <div class=\"secondary-path\">\
             <a id=\"back\" class=\"action\" href=\"/\">Back to IdentiKey</a>\
             </div>\
             {TECHNICAL_DETAILS}\
             <script>{COMMON_JS}\n{SIGNUP_JS}</script>"
        ),
    )
}

/// Signed-in first-party account page after hosted signup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPasskey {
    pub nickname: Option<String>,
    pub provider_name: Option<String>,
    pub icon: Option<String>,
    pub backed_up: Option<bool>,
    pub last_used: Option<String>,
    pub used_here: bool,
}

/// Public information only; private custody material never enters the renderer.
pub enum AccountManagedKey {
    Ed25519(String),
    LegacySchnorr,
    Unavailable,
}

#[must_use]
pub fn account(
    xid: &str,
    rung: &str,
    managed_key: &AccountManagedKey,
    passkeys: &[AccountPasskey],
) -> String {
    let xid = html_escape(xid);
    let rung = html_escape(rung);
    let passkeys = render_passkeys(passkeys);
    let managed_key = match managed_key {
        AccountManagedKey::Ed25519(public) => format!(
            "<p>Held by IdentiKey</p><p>Ed25519 operational public key (base64url): <code>{}</code></p>",
            html_escape(public)
        ),
        AccountManagedKey::LegacySchnorr =>
            "<p>Held by IdentiKey</p><p>This legacy Schnorr operational key is not usable for the responder.</p>".to_owned(),
        AccountManagedKey::Unavailable => "<p>No operational public key available.</p>".to_owned(),
    };
    shell(
        "Your account — IdentiKey",
        &format!(
            "<h1>Your IdentiKey</h1>\
             <p>This is the account you just created. Use the passkey you saved to sign in to apps that use IdentiKey.</p>\
             <dl class=\"facts\">\
             <dt>Account</dt><dd><code>{xid}</code></dd>\
             <dt>Custody</dt><dd>{rung}</dd>\
             <dt>Passkeys</dt><dd>{passkeys}</dd>\
             </dl>\
             <section aria-labelledby=\"managed-key-title\">\
             <h2 id=\"managed-key-title\">Operational key</h2>\
             {managed_key}</section>\
             <p>Keep the passkey. Creating another account will not restore this one.</p>\
             <p><a href=\"/signup\">Create a different account</a></p>"
        ),
    )
}

/// No session: do not create an account.
#[must_use]
pub fn account_signed_out() -> String {
    shell(
        "Your account — IdentiKey",
        "<h1>Your account</h1>\
         <p>This page appears after you create an account and save a passkey.</p>\
         <p><a href=\"/signup\">Create an account</a></p>",
    )
}

fn render_passkeys(passkeys: &[AccountPasskey]) -> String {
    if passkeys.is_empty() {
        return "No passkey saved yet".to_owned();
    }
    let rows = passkeys.iter().map(render_passkey).collect::<String>();
    format!("<ul class=\"passkeys\">{rows}</ul>")
}

fn render_passkey(passkey: &AccountPasskey) -> String {
    let label = passkey
        .nickname
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(passkey.provider_name.as_deref())
        .unwrap_or("Passkey");
    let label = html_escape(label);
    let icon = passkey.icon.as_deref().map_or_else(String::new, |src| {
        format!("<img src=\"{}\" alt=\"\"/>", html_escape(src))
    });
    let backup = match passkey.backed_up {
        Some(true) => "Backed up",
        Some(false) => "Not backed up",
        None => "Backup unknown",
    };
    let last_used = passkey.last_used.as_deref().map_or_else(
        || "Never used".to_owned(),
        |value| format!("Last used {}", html_escape(value)),
    );
    let here = if passkey.used_here {
        " · On this browser"
    } else {
        ""
    };
    format!(
        "<li class=\"passkey\"><div class=\"passkey-name\">{icon}<span>{label}</span></div>\
         <div class=\"passkey-meta\">{backup} · {last_used}{here}</div></li>"
    )
}

pub struct DeviceConfirm {
    pub user_code: String,
    pub display_name: String,
}

/// `GET /device`. A missing or rejected code is the type-in form.
/// A prefilled code shows the client and the code. The passkey approves it.
#[must_use]
pub fn device_confirm(confirm: Option<&DeviceConfirm>, rejected: bool) -> String {
    let form = match confirm {
        None => {
            let notice = if rejected {
                "<p id=\"reject\" class=\"status\">That code is not valid.</p>"
            } else {
                ""
            };
            format!(
                "{notice}\
                 <h1>Sign in</h1>\
                 <form method=\"get\" action=\"/device\">\
                 <label for=\"user_code\">Code</label>\
                 <input id=\"user_code\" name=\"user_code\" autocomplete=\"one-time-code\" required/>\
                 <button type=\"submit\">Continue</button>\
                 </form>"
            )
        }
        Some(confirm) => {
            let name = html_escape(&confirm.display_name);
            let code = html_escape(&confirm.user_code);
            let payload = json_for_script(
                &serde_json::json!({
                    "user_code": confirm.user_code,
                })
                .to_string(),
            );
            format!(
                "<h1>Sign in to {name}</h1>\
                 <p class=\"device-code\"><code>{code}</code></p>\
                 {STATUS_PANEL}\
                 <button type=\"button\" id=\"go\">Approve</button>\
                 <button type=\"button\" id=\"deny\" class=\"action\">Cancel</button>\
                 {TECHNICAL_DETAILS}\
                 <script type=\"application/json\" id=\"device\">{payload}</script>\
                 <script>{COMMON_JS}\n{DEVICE_JS}</script>"
            )
        }
    };
    shell("Sign in — IdentiKey", &format!("{LOCAL_NOTICE}{form}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_page_names_the_client_and_the_code() {
        let html = device_confirm(
            Some(&DeviceConfirm {
                user_code: "ABCD-EFGH".into(),
                display_name: "Mjolnir CLI".into(),
            }),
            false,
        );
        assert!(html.contains("Sign in to Mjolnir CLI"));
        assert!(html.contains("ABCD-EFGH"));
        assert!(html.contains(">Approve</button>"));
        assert!(!html.contains("checkbox"));
        assert!(!html.contains("must match"));
        assert!(!html.contains("base58btc"));
        assert!(!html.contains("Signed in"));
        let rejected = device_confirm(None, true);
        assert!(rejected.contains("That code is not valid."));
        assert!(!rejected.contains(">Approve</button>"));
    }

    #[test]
    fn managed_key_visibility_escapes_public_text_and_handles_absence() {
        let html = account(
            "xid",
            "Managed (C2)",
            &AccountManagedKey::Ed25519("<key>&".into()),
            &[],
        );
        assert!(html.contains("&lt;key&gt;&amp;"));
        assert!(!html.contains("<key>"));
        let absent = account(
            "xid",
            "Self-custody (C3)",
            &AccountManagedKey::Unavailable,
            &[],
        );
        assert!(absent.contains("No operational public key available."));
        assert!(!absent.contains("Held by IdentiKey"));
    }

    #[test]
    fn account_page_shows_xid_and_not_a_sub() {
        let html = account(
            "abc123",
            "Managed (C2)",
            &AccountManagedKey::Unavailable,
            &[AccountPasskey {
                nickname: None,
                provider_name: None,
                icon: None,
                backed_up: Some(false),
                last_used: None,
                used_here: false,
            }],
        );
        assert!(html.contains("abc123"));
        assert!(html.contains("Managed (C2)"));
        assert!(html.contains("Passkey"));
        assert!(!html.contains("pairwise"));
        assert!(signup().contains("/account"));
    }

    /// The recovery UI lives in pages-*.js/css. Those files existed for a
    /// week without being embedded, so pin the wiring and the ids they use.
    #[test]
    fn hosted_pages_embed_recovery_ui() {
        let login = passkey_login(r#"{"session":"s","publicKey":{}}"#, &[]);
        assert!(!login.contains("device-passkeys"));
        let remembered = passkey_login(
            r#"{"session":"s","publicKey":{}}"#,
            &["1Password".into(), "Desk <mac>".into()],
        );
        assert!(remembered.contains("This browser has used 1Password and Desk &lt;mac&gt;."));
        assert!(!remembered.contains("Desk <mac>"));
        for id in [
            "status",
            "status-title",
            "status-description",
            "technical",
            "technical-message",
            "passkey-help",
            "local-notice",
            "signup",
            "go",
            "ceremony",
        ] {
            assert!(login.contains(&format!("id=\"{id}\"")), "login lacks #{id}");
        }
        assert!(login.contains("function showFailure"));
        assert!(login.contains("async function freshOptions"));
        let signup = signup();
        for id in ["status", "technical", "back", "go", "local-notice"] {
            assert!(
                signup.contains(&format!("id=\"{id}\"")),
                "signup lacks #{id}"
            );
        }
        assert!(signup.contains("/webauthn/register/begin"));
        assert!(signup.contains(".secondary-path"));
    }

    #[test]
    fn passkey_legibility_uses_nickname_before_provider_and_escapes_both() {
        let html = account(
            "abc123",
            "Managed (C2)",
            &AccountManagedKey::Unavailable,
            &[AccountPasskey {
                nickname: Some("  Work <key>  ".into()),
                provider_name: Some("Provider <ignored>".into()),
                icon: Some("data:image/svg+xml;base64,PHN2Zy8+\" onerror=\"x".into()),
                backed_up: Some(true),
                last_used: Some("2026-09-27 12:34:56 +00:00".into()),
                used_here: true,
            }],
        );
        assert!(html.contains("On this browser"));
        assert!(html.contains("Work &lt;key&gt;"));
        assert!(!html.contains("Provider &lt;ignored&gt;"));
        assert!(html.contains("&quot; onerror=&quot;x"));
        assert!(html.contains("Backed up"));
        assert!(html.contains("Last used 2026-09-27"));
    }

    #[test]
    fn passkey_legibility_unknown_aaguid_falls_back_to_passkey() {
        let html = account(
            "abc123",
            "Managed (C2)",
            &AccountManagedKey::Unavailable,
            &[AccountPasskey {
                nickname: None,
                provider_name: None,
                icon: None,
                backed_up: Some(false),
                last_used: None,
                used_here: false,
            }],
        );
        assert!(html.contains("<span>Passkey</span>"));
        assert!(html.contains("Not backed up · Never used"));
    }

    #[test]
    fn passkey_legibility_unknown_backup_is_distinct_from_stored_false() {
        for (backed_up, expected) in [
            (None, "Backup unknown"),
            (Some(false), "Not backed up"),
            (Some(true), "Backed up"),
        ] {
            let html = account(
                "abc123",
                "Managed (C2)",
                &AccountManagedKey::Unavailable,
                &[AccountPasskey {
                    nickname: None,
                    provider_name: None,
                    icon: None,
                    backed_up,
                    last_used: None,
                    used_here: false,
                }],
            );
            assert!(html.contains(&format!("{expected} · Never used")));
            assert_eq!(html.contains("Backup unknown"), backed_up.is_none());
            assert_eq!(html.contains("Not backed up"), backed_up == Some(false));
        }
    }

    #[test]
    fn passkey_legibility_escapes_provider_metadata_without_a_nickname() {
        let html = account(
            "abc123",
            "Managed (C2)",
            &AccountManagedKey::Unavailable,
            &[AccountPasskey {
                nickname: None,
                provider_name: Some("Provider <unsafe> & friends".into()),
                icon: None,
                backed_up: Some(false),
                last_used: None,
                used_here: false,
            }],
        );
        assert!(html.contains("Provider &lt;unsafe&gt; &amp; friends"));
        assert!(!html.contains("Provider <unsafe>"));
    }
}
