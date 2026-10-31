function b64urlToBuf(t) {
  t = String(t).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
}
function bufToB64url(buf) {
  let s = "";
  for (const byte of new Uint8Array(buf)) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decodePublicKey(pk) {
  pk.challenge = b64urlToBuf(pk.challenge);
  if (pk.user?.id) pk.user.id = b64urlToBuf(pk.user.id);
  for (const c of pk.allowCredentials || []) c.id = b64urlToBuf(c.id);
  for (const c of pk.excludeCredentials || []) c.id = b64urlToBuf(c.id);
  return pk;
}
function credToJson(cred) {
  const response = {};
  for (const name of [
    "clientDataJSON",
    "authenticatorData",
    "signature",
    "userHandle",
    "attestationObject",
  ]) {
    if (cred.response[name]) response[name] = bufToB64url(cred.response[name]);
  }
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response,
  };
}
async function request(url, options = {}) {
  try {
    return await fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
  } catch (cause) {
    const error = new Error(cause.message);
    error.name = "NetworkError";
    throw error;
  }
}
function postJson(url, body) {
  return request(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
}
async function responseError(res) {
  const body = await res.text();
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    /* Non-JSON failures still get a useful status. */
  }
  const error = new Error(
    data?.error_description || `Unexpected response (HTTP ${res.status})`,
  );
  error.name = "ResponseError";
  error.status = res.status;
  error.code = data?.error || "unexpected_response";
  return error;
}
let stage = "prepare";
let lastReport = null;
function setStage(next) {
  stage = next;
}
function buildReport(error) {
  const report = {
    stage: error.stage || stage,
    secure_context: Boolean(window.isSecureContext),
    public_key_credential: Boolean(window.PublicKeyCredential),
    navigator_credentials: Boolean(navigator.credentials),
    error_name: error.name || "Error",
  };
  if (typeof error.code === "string") report.server_error = error.code;
  if (typeof error.status === "number") report.http_status = error.status;
  return report;
}
async function copyReport() {
  const result = document.getElementById("copy-result");
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
    result.textContent = "Diagnostics copied. Nothing was sent.";
  } catch {
    result.textContent = "The copy did not happen. Your status is unchanged.";
  }
}
function clearStatus() {
  lastReport = null;
  document.getElementById("copy-report").hidden = true;
  document.getElementById("copy-result").textContent = "";
  document.getElementById("status").hidden = true;
  const technical = document.getElementById("technical");
  technical.hidden = true;
  technical.open = false;
  document.getElementById("technical-message").textContent = "";
}
function status(title, message, ok = false) {
  const panel = document.getElementById("status");
  document.getElementById("status-title").textContent = title;
  document.getElementById("status-description").textContent = message;
  panel.className = ok ? "status ok" : "status";
  panel.hidden = false;
  panel.focus();
}
function showFailure(error, creating = false) {
  let title = "We couldn't finish signing you in.";
  let message =
    "Try again. If this keeps happening, return to the app and start sign-in again.";
  let help = false;
  if (error.message === "credential not found") {
    title = "That passkey isn't registered here.";
    message =
      "Try a different passkey from your password manager or another device. If you haven't created an account here, choose Create an account below.";
    help = true;
  } else if (error.message === "unknown or expired ceremony") {
    title = "This attempt has expired.";
    message =
      "Try again to start a fresh attempt. Your saved passkey has not changed.";
  } else if (error.name === "NotAllowedError" || error.name === "AbortError") {
    title = creating
      ? "Passkey setup was not completed."
      : "The passkey prompt was not completed.";
    message =
      "The browser ended the prompt without a passkey. This can happen for several reasons, and it does not mean your account is missing. Try again, or choose a different password manager or device in the prompt.";
    help = !creating;
  } else if (error.name === "InvalidStateError" && creating) {
    title = "A passkey may already be saved.";
    message =
      "Try signing in with your existing passkey, or choose another place to save this one.";
  } else if (
    error.name === "SecurityError" ||
    error.name === "NotSupportedError"
  ) {
    title = "Passkeys are not available in this browser or on this address.";
    message =
      "Open the original app link in an up-to-date browser that supports passkeys, using a secure connection.";
  } else if (error.name === "NetworkError") {
    title = "We couldn't reach IdentiKey.";
    message =
      "Check your connection, then try again. You do not need to create another account.";
  } else if (error.status >= 500) {
    title = "IdentiKey is temporarily unavailable.";
    message =
      "Try again in a moment. You do not need to create another account.";
  } else if (error.name === "SignInRequestError") {
    title = "This sign-in link could not be renewed.";
    message = "Return to the app that sent you here and start sign-in again.";
  } else if (creating) {
    title = "We couldn't finish saving your passkey.";
    message =
      "Try again using the same account setup, or go back to sign-in if you already have an account.";
  }
  status(title, message);
  lastReport = buildReport(error);
  const copy = document.getElementById("copy-report");
  copy.hidden = false;
  document.getElementById("copy-result").textContent = "";
  const details = document.getElementById("technical");
  document.getElementById("technical-message").textContent = JSON.stringify(
    {
      error: error.code || error.name,
      error_description: error.message,
      http_status: error.status,
    },
    null,
    2,
  );
  details.hidden = false;
  const tips = document.getElementById("passkey-help");
  if (help && tips) tips.open = true;
}
function setBusy(label) {
  const button = document.getElementById("go");
  button.disabled = true;
  button.textContent = label;
  button.setAttribute("aria-busy", "true");
}
function setReady(label) {
  const button = document.getElementById("go");
  button.disabled = false;
  button.textContent = label;
  button.removeAttribute("aria-busy");
}
function checkSupport() {
  if (
    window.isSecureContext &&
    window.PublicKeyCredential &&
    navigator.credentials
  )
    return true;
  const error = new Error(
    "WebAuthn unavailable or origin is not a secure context",
  );
  error.name = "NotSupportedError";
  setStage("support");
  showFailure(error);
  document.getElementById("go").disabled = true;
  return false;
}
document.getElementById("copy-report").addEventListener("click", copyReport);
if (["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)) {
  document.getElementById("local-notice").hidden = false;
}

// Provider hygiene is best effort and never gates the accepted ceremony.
function signalAccepted(result, rpId) {
  if (!result.signal_user_id || !Array.isArray(result.signal_credential_ids) ||
      result.signal_credential_ids.length === 0) return;
  try {
    Promise.resolve(window.PublicKeyCredential?.signalAllAcceptedCredentials?.({
      rpId,
      userId: b64urlToBuf(result.signal_user_id),
      allAcceptedCredentialIds: result.signal_credential_ids,
    })).catch(() => {});
  } catch { /* A provider failure must not block navigation. */ }
}
function signalUnknown(error, rpId, credentialId) {
  if (error.name !== "ResponseError" || error.message !== "credential not found" ||
      rpId === "localhost") return;
  try {
    Promise.resolve(window.PublicKeyCredential?.signalUnknownCredential?.({
      rpId, credentialId,
    })).catch(() => {});
  } catch { /* Keep the original ceremony failure. */ }
}
