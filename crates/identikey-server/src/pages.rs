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
    headers:{'content-type':'application/json'},
    body:JSON.stringify(body),
    redirect:'manual'
  });
}
function followRedirect(res){
  if(res.status>=300&&res.status<400){
    const loc=res.headers.get('Location');
    if(loc){location.assign(loc);return true;}
  }
  if(res.redirected&&res.url){location.assign(res.url);return true;}
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
             <p>Use your passkey. No username.</p>\
             <p id=\"status\" class=\"status\"></p>\
             <button type=\"button\" id=\"go\">Continue with passkey</button>\
             <p style=\"margin-top:1.25rem\">New here? <a href=\"/signup\">Create an account</a></p>\
             <script type=\"application/json\" id=\"ceremony\">{json}</script>\
             <script>{WEBAUTHN_JS}\
             const opts=JSON.parse(document.getElementById('ceremony').textContent);\
             async function assertPasskey(modal){{\
               const btn=document.getElementById('go');\
               btn.disabled=true;\
               setStatus('');\
               try{{\
                 const pk=decodePublicKey(structuredClone(opts.publicKey));\
                 const getOpts={{publicKey:pk}};\
                 if(!modal&&await canConditional())getOpts.mediation='conditional';\
                 const cred=await navigator.credentials.get(getOpts);\
                 if(!cred){{setStatus('No passkey selected.');btn.disabled=false;return;}}\
                 const res=await postJson('/webauthn/assert/finish',{{\
                   session:opts.session,\
                   credential:credToJson(cred)\
                 }});\
                 if(followRedirect(res))return;\
                 const text=await res.text();\
                 setStatus(text||('Sign-in failed ('+res.status+').'));\
               }}catch(e){{setStatus(e&&e.message?e.message:String(e));}}\
               btn.disabled=false;\
             }}\
             document.getElementById('go').addEventListener('click',()=>assertPasskey(true));\
             assertPasskey(false);\
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
             <p>We will create a managed identity and enroll a passkey on this device. \
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
                 setStatus('Passkey saved. Return to the app you were signing into and use it.',true);\
                 btn.textContent='Done';\
                 return;\
               }}catch(e){{setStatus(e&&e.message?e.message:String(e));}}\
               btn.disabled=false;\
             }}\
             document.getElementById('go').addEventListener('click',signup);\
             </script>"
        ),
    )
}
