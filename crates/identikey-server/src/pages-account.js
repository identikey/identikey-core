const accountXid = JSON.parse(document.getElementById("account-data").textContent).xid;
const lastAccess = document.getElementById("last-access");
let pendingRevoke = null;
let busy = false;

async function managePasskey(action) {
  if (busy) return;
  busy = true;
  clearStatus();
  try {
    await action();
  } catch (error) {
    showFailure(error, true);
  } finally {
    busy = false;
    setReady("Add a passkey");
  }
}

async function revokePasskey(id, confirmLastAccess = false) {
  const response = await postJson(`/account/passkeys/${id}/revoke`, {
    confirm_last_access: confirmLastAccess,
  });
  if (response.status === 409) {
    const body = await response.json();
    if (body.error === "last_access_confirmation_required") {
      pendingRevoke = id;
      lastAccess.hidden = false;
      document.getElementById("cancel-last-access").focus();
      return;
    }
    throw new Error("Could not revoke this passkey. Refresh and try again.");
  }
  if (!response.ok) throw await responseError(response);
  location.reload();
}

for (const row of document.querySelectorAll("[data-passkey-id]")) {
  const id = row.dataset.passkeyId;
  row.querySelector(".passkey-nickname").addEventListener("submit", (event) => {
    event.preventDefault();
    managePasskey(async () => {
      const response = await postJson(`/account/passkeys/${id}/nickname`, {
        nickname: row.querySelector("input[name=nickname]").value,
      });
      if (!response.ok) throw await responseError(response);
      location.reload();
    });
  });
  row.querySelector(".revoke-passkey").addEventListener("click", () => {
    managePasskey(async () => {
      pendingRevoke = null;
      lastAccess.hidden = true;
      await revokePasskey(id);
    });
  });
}
document.getElementById("confirm-last-access").addEventListener("click", () => {
  if (pendingRevoke) managePasskey(() => revokePasskey(pendingRevoke, true));
});
document.getElementById("cancel-last-access").addEventListener("click", () => {
  pendingRevoke = null;
  lastAccess.hidden = true;
});
document.getElementById("go").addEventListener("click", () => {
  managePasskey(async () => {
    pendingRevoke = null;
    lastAccess.hidden = true;
    setStage("prepare");
    setBusy("Preparing your passkey…");
    const begun = await postJson("/webauthn/register/begin", { xid: accountXid });
    if (!begun.ok) throw await responseError(begun);
    const pending = await begun.json();
    setStage("prompt");
    setBusy("Save your passkey in the prompt…");
    const credential = await navigator.credentials.create({
      publicKey: decodePublicKey(structuredClone(pending.publicKey)),
    });
    if (!credential) throw new DOMException("No credential returned", "NotAllowedError");
    setStage("finish");
    const response = await postJson("/webauthn/register/finish", {
      session: pending.session,
      xid: accountXid,
      credential: credToJson(credential),
    });
    if (!response.ok) throw await responseError(response);
    signalAccepted(await response.json(), pending.publicKey.rp.id);
    location.reload();
  });
});
checkSupport();
