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

const SHELL_CSS: &str = "\
body{margin:0;min-height:100vh;font:16px/1.45 system-ui,sans-serif;\
background:#0f1419;color:#e7ecf1;display:flex;align-items:center;justify-content:center}\
main{width:min(28rem,calc(100% - 2rem));background:#1a222c;border-radius:12px;\
padding:1.75rem 1.5rem 1.5rem;box-shadow:0 12px 40px #0008}\
h1{font-size:1.25rem;margin:0 0 .35rem}\
p{margin:.35rem 0 1rem;color:#b7c2cc}\
button{appearance:none;border:0;border-radius:8px;padding:.7rem 1rem;\
font:inherit;font-weight:600;background:#5b8def;color:#fff;cursor:pointer;width:100%}\
button:disabled{opacity:.55;cursor:not-allowed}\
button.secondary{background:#2a3542;margin-top:.6rem}\
a{color:#8bb4ff}\
.status{min-height:1.4em;color:#f0b4b4;margin:0 0 1rem}\
.status.ok{color:#9ed4b0}\
.facts{margin:0 0 1rem}.facts dt{color:#b7c2cc;font-size:.875rem;margin-top:.75rem}\
.facts dd{margin:.15rem 0 0}.facts code{display:block;overflow-wrap:anywhere;font:.8125rem/1.45 ui-monospace,monospace}\
";

const WEBAUTHN_JS: &str = r#"
function b64urlToBuf(t){
  t=String(t).replace(/-/g,'+').replace(/_/g,'/');
  while(t.length%4)t+='=';
  return Uint8Array.from(atob(t),c=>c.charCodeAt(0));
}
function bufToB64url(buf){
  const u8=new Uint8Array(buf);
  let s='';
  for(let i=0;i<u8.length;i++)s+=String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function decodePublicKey(pk){
  pk.challenge=b64urlToBuf(pk.challenge);
  if(pk.user&&pk.user.id)pk.user.id=b64urlToBuf(pk.user.id);
  if(pk.allowCredentials)for(const c of pk.allowCredentials)c.id=b64urlToBuf(c.id);
  if(pk.excludeCredentials)for(const c of pk.excludeCredentials)c.id=b64urlToBuf(c.id);
  return pk;
}
function credToJson(cred){
  const out={
    id:cred.id,
    rawId:bufToB64url(cred.rawId),
    type:cred.type,
    response:{}
  };
  const r=cred.response;
  if(r.clientDataJSON)out.response.clientDataJSON=bufToB64url(r.clientDataJSON);
  if(r.authenticatorData)out.response.authenticatorData=bufToB64url(r.authenticatorData);
  if(r.signature)out.response.signature=bufToB64url(r.signature);
  if(r.userHandle)out.response.userHandle=bufToB64url(r.userHandle);
  if(r.attestationObject)out.response.attestationObject=bufToB64url(r.attestationObject);
  return out;
}
async function postJson(url,body){
  return fetch(url,{
    method:'POST',
    headers:{'content-type':'application/json','accept':'application/json'},
    body:JSON.stringify(body)
  });
}
async function followRedirect(res){
  const ct=res.headers.get('content-type')||'';
  if(ct.includes('json')){
    const data=await res.clone().json().catch(()=>null);
    if(data&&data.redirect){location.assign(data.redirect);return true;}
  }
  const loc=res.headers.get('Location');
  if(loc){location.assign(loc);return true;}
  if(res.redirected&&res.url&&res.url!==location.href){location.assign(res.url);return true;}
  return false;
}
async function canConditional(){
  try{
    return !!(window.PublicKeyCredential
      &&PublicKeyCredential.isConditionalMediationAvailable
      &&await PublicKeyCredential.isConditionalMediationAvailable());
  }catch(_){return false;}
}
function setStatus(msg,ok){
  const el=document.getElementById('status');
  if(!el)return;
  el.textContent=msg||'';
  el.className=ok?'status ok':'status';
}
"#;

fn shell(title: &str, inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/>\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>\
         <title>{}</title><style>{SHELL_CSS}</style></head>\
         <body><main>{}</main></body></html>",
        html_escape(title),
        inner
    )
}

/// Production assertion page for `GET /authorize/passkey`.
#[must_use]
pub fn passkey_login(ceremony_json: &str) -> String {
    let json = json_for_script(ceremony_json);
    shell(
        "Sign in — IdentiKey",
        &format!(
            "<h1>Sign in</h1>\
             <p>Use a passkey from 1Password, iCloud Keychain, or this device. No username.</p>\
             <p id=\"status\" class=\"status\"></p>\
             <button type=\"button\" id=\"go\">Continue with passkey</button>\
             <p style=\"margin-top:1.25rem\">New here? <a id=\"signup\" href=\"/signup\">Create an account</a></p>\
             <script type=\"application/json\" id=\"ceremony\">{json}</script>\
             <script>{WEBAUTHN_JS}\
             const opts=JSON.parse(document.getElementById('ceremony').textContent);\
             const signup=document.getElementById('signup');\
             if(signup)signup.href='/signup'+location.search;\
             let phase='idle';\
             let abort=null;\
             async function assertPasskey(modal){{\
               if(phase==='finishing')return;\
               if(phase==='getting'){{\
                 if(!modal)return;\
                 if(abort)abort.abort();\
               }}\
               phase='getting';\
               const btn=document.getElementById('go');\
               btn.disabled=true;\
               setStatus('');\
               abort=new AbortController();\
               try{{\
                 const pk=decodePublicKey(structuredClone(opts.publicKey));\
                 const getOpts={{publicKey:pk,signal:abort.signal}};\
                 if(!modal&&await canConditional())getOpts.mediation='conditional';\
                 const cred=await navigator.credentials.get(getOpts);\
                 if(!cred){{setStatus(modal?'No passkey selected.':'');phase='idle';btn.disabled=false;return;}}\
                 phase='finishing';\
                 const res=await postJson('/webauthn/assert/finish',{{\
                   session:opts.session,\
                   credential:credToJson(cred)\
                 }});\
                 if(await followRedirect(res))return;\
                 const text=await res.text();\
                 let expired=false;\
                 try{{expired=JSON.parse(text).error_description==='unknown or expired ceremony';}}catch(_){{}}\
                 if(expired){{setStatus('That sign-in expired. Trying again…');location.reload();return;}}\
                 setStatus(text||('Sign-in failed ('+res.status+').'));\
                 phase='idle';\
               }}catch(e){{\
                 if(e&&e.name==='AbortError'){{phase='idle';btn.disabled=false;return;}}\
                 setStatus(e&&e.message?e.message:String(e));\
                 phase='idle';\
               }}\
               btn.disabled=false;\
             }}\
             document.getElementById('go').addEventListener('click',()=>assertPasskey(true));\
             </script>"
        ),
    )
}

/// `GET /signup` — creates nothing until POST.
#[must_use]
pub fn signup() -> String {
    shell(
        "Create account — IdentiKey",
        &format!(
            "<h1>Create an account</h1>\
             <p>We will create a managed identity and enroll a passkey. Save it in \
             1Password (or iCloud Keychain / this device) when the browser asks. \
             This is access, not your Elect key.</p>\
             <p id=\"status\" class=\"status\"></p>\
             <button type=\"button\" id=\"go\">Create account and add a passkey</button>\
             <script>{WEBAUTHN_JS}\
             async function signup(){{\
               const btn=document.getElementById('go');\
               btn.disabled=true;\
               setStatus('');\
               try{{\
                 const created=await fetch('/signup',{{method:'POST'}});\
                 if(!created.ok){{\
                   setStatus(await created.text()||('Signup failed ('+created.status+').'));\
                   btn.disabled=false;return;\
                 }}\
                 const opts=await created.json();\
                 const pk=decodePublicKey(opts.publicKey);\
                 const cred=await navigator.credentials.create({{publicKey:pk}});\
                 if(!cred){{setStatus('Passkey creation was cancelled.');btn.disabled=false;return;}}\
                 const res=await postJson('/webauthn/register/finish',{{\
                   session:opts.session,\
                   xid:opts.xid,\
                   credential:credToJson(cred)\
                 }});\
                 if(!res.ok){{\
                   setStatus(await res.text()||('Could not save the passkey ('+res.status+').'));\
                   btn.disabled=false;return;\
                 }}\
                 if(location.search.indexOf('client_id=')>=0){{\
                   location.assign('/authorize/passkey'+location.search);\
                   return;\
                 }}\
                 const body=await res.json().catch(()=>({{}}));\
                 location.assign(body.next||'/account');\
                 return;\
               }}catch(e){{setStatus(e&&e.message?e.message:String(e));}}\
               btn.disabled=false;\
             }}\
             document.getElementById('go').addEventListener('click',signup);\
             </script>"
        ),
    )
}

/// Signed-in first-party account page after hosted signup.
#[must_use]
pub fn account(xid: &str, rung: &str, passkeys: usize) -> String {
    let xid = html_escape(xid);
    let rung = html_escape(rung);
    let passkeys = html_escape(&passkey_label(passkeys));
    shell(
        "Your account — IdentiKey",
        &format!(
            "<h1>Your IdentiKey</h1>\
             <p>This is the account you just created. Use the passkey you saved to sign in to apps that use IdentiKey.</p>\
             <dl class=\"facts\">\
             <dt>Account</dt><dd><code>{xid}</code></dd>\
             <dt>Custody</dt><dd>{rung}</dd>\
             <dt>Sign-in</dt><dd>{passkeys}</dd>\
             </dl>\
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

fn passkey_label(n: usize) -> String {
    match n {
        0 => "No passkey saved yet".to_owned(),
        1 => "1 passkey".to_owned(),
        n => format!("{n} passkeys"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_page_shows_xid_and_not_a_sub() {
        let html = account("abc123", "Managed (C2)", 1);
        assert!(html.contains("abc123"));
        assert!(html.contains("Managed (C2)"));
        assert!(html.contains("1 passkey"));
        assert!(!html.contains("pairwise"));
        assert!(signup().contains("/account"));
    }
}
