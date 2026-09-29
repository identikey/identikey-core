let options = JSON.parse(document.getElementById("ceremony").textContent);
let renew = false;
let busy = false;
document.getElementById("signup").href = "/signup" + location.search;
if (location.hash === "#passkey-saved") {
  status(
    "Your passkey is saved.",
    "Choose it once more to finish signing in and return to your app.",
    true,
  );
  history.replaceState(null, "", location.pathname + location.search);
}

async function freshOptions() {
  const response = await request("/authorize/passkey" + location.search, {
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) throw await responseError(response);
  const doc = new DOMParser().parseFromString(
    await response.text(),
    "text/html",
  );
  const ceremony = doc.getElementById("ceremony");
  if (!ceremony) {
    const error = new Error("Renewed authorization response has no ceremony");
    error.name = "SignInRequestError";
    throw error;
  }
  options = JSON.parse(ceremony.textContent);
}

async function signIn() {
  if (busy) return;
  busy = true;
  clearStatus();
  setBusy("Opening passkey prompt…");
  try {
    if (renew) await freshOptions();
    // Every retry gets a fresh challenge, including a delayed/cancelled prompt.
    renew = true;
    const credential = await navigator.credentials.get({
      publicKey: decodePublicKey(structuredClone(options.publicKey)),
    });
    if (!credential)
      throw new DOMException("No credential returned", "NotAllowedError");
    setBusy("Signing in…");
    const response = await postJson("/webauthn/assert/finish", {
      session: options.session,
      credential: credToJson(credential),
    });
    if (!response.ok) throw await responseError(response);
    const result = await response.json();
    if (!result.redirect)
      throw new Error("Authorization response is missing its redirect");
    location.assign(result.redirect);
    return;
  } catch (error) {
    showFailure(error);
    setReady(
      error.message === "credential not found"
        ? "Try another passkey"
        : "Try again",
    );
    busy = false;
  }
}
document.getElementById("go").addEventListener("click", signIn);
checkSupport();
