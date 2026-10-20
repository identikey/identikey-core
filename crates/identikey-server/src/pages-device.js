const device = JSON.parse(document.getElementById("device").textContent);
const go = document.getElementById("go");
const deny = document.getElementById("deny");
let busy = false;

function finish(title) {
  document.querySelector("h1").textContent = title;
  go.hidden = true;
  deny.hidden = true;
  clearStatus();
}

async function approve() {
  if (busy) return;
  busy = true;
  go.disabled = true;
  clearStatus();
  setBusy("Approve");
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
    const finished = await postJson("/device/assert/finish", {
      session: options.session,
      credential: credToJson(credential),
      confirmed: true,
    });
    if (!finished.ok) throw await responseError(finished);
    finish("Approved");
  } catch (error) {
    showFailure(error);
    busy = false;
    setReady("Approve");
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
    finish("Cancelled");
  } catch (error) {
    showFailure(error);
    busy = false;
    deny.disabled = false;
    setReady("Approve");
  }
}

go.addEventListener("click", approve);
deny.addEventListener("click", refuse);
checkSupport();
