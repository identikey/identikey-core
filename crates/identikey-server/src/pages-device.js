const device = JSON.parse(document.getElementById("device").textContent);
const confirm = document.getElementById("confirm");
const go = document.getElementById("go");
const deny = document.getElementById("deny");
let busy = false;

confirm.addEventListener("change", () => {
  go.disabled = !confirm.checked || busy;
});

async function approve() {
  if (busy || !confirm.checked) return;
  busy = true;
  go.disabled = true;
  clearStatus();
  setBusy("Opening passkey prompt…");
  try {
    const began = await postJson("/device/assert/begin", {
      user_code: device.user_code,
    });
    if (!began.ok) throw await responseError(began);
    const options = await began.json();
    const credential = await navigator.credentials.get({
      publicKey: decodePublicKey(structuredClone(options.publicKey)),
    });
    if (!credential)
      throw new DOMException("No credential returned", "NotAllowedError");
    setBusy("Approving…");
    const finished = await postJson("/device/assert/finish", {
      session: options.session,
      credential: credToJson(credential),
      confirmed: confirm.checked === true,
    });
    if (!finished.ok) throw await responseError(finished);
    status(
      "Signed in.",
      "You can return to the terminal. This page does not keep a session for that program.",
      true,
    );
    go.hidden = true;
    deny.hidden = true;
    confirm.disabled = true;
  } catch (error) {
    showFailure(error);
    busy = false;
    go.disabled = !confirm.checked;
    setReady("Try again");
  }
}

async function refuse() {
  if (busy) return;
  busy = true;
  go.disabled = true;
  deny.disabled = true;
  clearStatus();
  try {
    const response = await postJson("/device/deny", {
      user_code: device.user_code,
    });
    if (!response.ok) throw await responseError(response);
    status(
      "Sign-in refused.",
      "The terminal will not receive a token. If you did not start this, you can close the page.",
      true,
    );
  } catch (error) {
    showFailure(error);
    busy = false;
    deny.disabled = false;
    go.disabled = !confirm.checked;
  }
}

go.addEventListener("click", approve);
deny.addEventListener("click", refuse);
checkSupport();
