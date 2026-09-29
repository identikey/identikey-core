let pending = null;
let busy = false;
const hasApp = new URLSearchParams(location.search).has("client_id");
const back = document.getElementById("back");
back.href = hasApp ? "/authorize/passkey" + location.search : "/";
back.textContent = hasApp ? "Back to sign in" : "Back to IdentiKey";

async function signUp() {
  if (busy) return;
  busy = true;
  clearStatus();
  setBusy("Preparing your passkey…");
  try {
    if (!pending) {
      const created = await request("/signup", { method: "POST" });
      if (!created.ok) throw await responseError(created);
      pending = await created.json();
    } else {
      // Retrying a cancelled/failed ceremony must not create another identity.
      const begun = await postJson("/webauthn/register/begin", {
        xid: pending.xid,
      });
      if (!begun.ok) throw await responseError(begun);
      pending = { ...(await begun.json()), xid: pending.xid };
    }
    setBusy("Save your passkey in the prompt…");
    const credential = await navigator.credentials.create({
      publicKey: decodePublicKey(structuredClone(pending.publicKey)),
    });
    if (!credential)
      throw new DOMException("No credential returned", "NotAllowedError");
    setBusy("Saving your passkey…");
    const response = await postJson("/webauthn/register/finish", {
      session: pending.session,
      xid: pending.xid,
      credential: credToJson(credential),
    });
    if (!response.ok) throw await responseError(response);
    if (hasApp) {
      location.assign(
        "/authorize/passkey" + location.search + "#passkey-saved",
      );
    } else {
      const body = await response.json().catch(() => ({}));
      location.assign(body.next || "/account");
    }
  } catch (error) {
    showFailure(error, true);
    setReady("Try saving a passkey again");
    busy = false;
  }
}
document.getElementById("go").addEventListener("click", signUp);
checkSupport();
