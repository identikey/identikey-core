import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

// Against a running local OP (scripts/dev-server.sh; defaults match .env.example).
// An unregistered virtual key exercises the actual API; other failures are
// intercepted. No accounts are created.
const origin = process.env.IDENTIKEY_ORIGIN ?? 'http://localhost:8080';
const query = new URLSearchParams({
	client_id: process.env.IDENTIKEY_CLIENT_ID ?? 'smoke',
	redirect_uri: process.env.IDENTIKEY_CLIENT_REDIRECT ?? 'http://127.0.0.1:9999/cb',
	response_type: 'code',
	scope: 'openid',
	state: 'ux-test-state',
	nonce: 'ux-test-nonce',
	code_challenge_method: 'S256',
	code_challenge: createHash('sha256').update('ux-test-verifier'.repeat(4)).digest('base64url')
}).toString();
let browser;
before(async () => {
	const executablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH;
	browser = await chromium.launch(
		executablePath ? { executablePath, headless: true } : { channel: 'chrome', headless: true }
	);
});
after(async () => {
	await browser?.close();
});

test('real unregistered authenticator shows recovery at desktop and mobile sizes', async (t) => {
	const context = await browser.newContext();
	t.after(() => context.close());
	const page = await context.newPage();
	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'internal',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true
		}
	});
	const { privateKey } = generateKeyPairSync('ec', {
		namedCurve: 'prime256v1',
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
		publicKeyEncoding: { type: 'spki', format: 'der' }
	});
	await cdp.send('WebAuthn.addCredential', {
		authenticatorId,
		credential: {
			credentialId: randomBytes(32).toString('base64'),
			isResidentCredential: true,
			rpId: 'localhost',
			privateKey: privateKey.toString('base64'),
			userHandle: randomBytes(32).toString('base64'),
			signCount: 0
		}
	});
	await page.goto(`${origin}/authorize/passkey?${query}`);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: "That passkey isn't registered here." }).waitFor();
	assert.equal(
		JSON.parse(await page.locator('#technical-message').textContent()).error_description,
		'credential not found'
	);
	await page.screenshot({ path: `${tmpdir()}/identikey-recovery-desktop.png`, fullPage: true });
	await page.setViewportSize({ width: 390, height: 844 });
	assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
	await page.screenshot({ path: `${tmpdir()}/identikey-recovery-mobile.png`, fullPage: true });
});

async function pageFor(t, kind = 'login', viewport) {
	const context = await browser.newContext({ viewport });
	t.after(() => context.close());
	const page = await context.newPage();
	page.setDefaultTimeout(5000);
	await page.addInitScript(() => {
		const credential = () => ({
			id: 'test',
			rawId: new ArrayBuffer(4),
			type: 'public-key',
			response: {}
		});
		Object.defineProperty(navigator.credentials, 'get', {
			configurable: true,
			value: async () => credential()
		});
		Object.defineProperty(navigator.credentials, 'create', {
			configurable: true,
			value: async () => credential()
		});
	});
	await page.goto(`${origin}/${kind === 'login' ? 'authorize/passkey' : 'signup'}?${query}`);
	return page;
}
const failure = (route, description, status = 400) =>
	route.fulfill({
		status,
		contentType: 'application/json',
		body: JSON.stringify({ error: 'invalid_request', error_description: description })
	});

test('unknown credential offers recovery, hides diagnostics and renews the challenge on retry', async (t) => {
	const page = await pageFor(t);
	const sessions = [];
	await page.route('**/webauthn/assert/finish', (route) => {
		sessions.push(route.request().postDataJSON().session);
		return failure(route, 'credential not found');
	});
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: "That passkey isn't registered here." }).waitFor();
	assert.equal(await page.locator('#technical').getAttribute('open'), null);
	assert.equal(await page.locator('#technical-message').isVisible(), false);
	assert.equal(await page.locator('#passkey-help').getAttribute('open'), '');
	assert.equal(await page.evaluate(() => document.activeElement.id), 'status');
	assert.ok(!(await page.locator('#status').innerText()).includes('invalid_request'));
	await page.getByText('Technical details', { exact: true }).click();
	const details = JSON.parse(await page.locator('#technical-message').textContent());
	assert.equal(details.error_description, 'credential not found');
	assert.equal(details.http_status, 400);
	await page.getByRole('button', { name: 'Try another passkey' }).click();
	await page.getByRole('heading', { name: "That passkey isn't registered here." }).waitFor();
	assert.equal(sessions.length, 2);
	assert.notEqual(sessions[0], sessions[1]);
	const signup = new URL(await page.locator('#signup').getAttribute('href'), origin);
	assert.equal(signup.searchParams.get('state'), 'ux-test-state');
	assert.equal(
		signup.searchParams.get('code_challenge'),
		new URLSearchParams(query).get('code_challenge')
	);
});

test('signup completion explains the final sign-in step without changing OIDC context', async (t) => {
	const page = await pageFor(t);
	// Arrive from a different document, as signup does; a hash-only navigation
	// on the same login document would not rerun its initialization script.
	await page.goto('about:blank');
	await page.goto(`${origin}/authorize/passkey?${query}#passkey-saved`);
	await page.getByRole('heading', { name: 'Your passkey is saved.' }).waitFor();
	assert.equal(new URL(page.url()).hash, '');
	assert.equal(new URL(page.url()).search, '?' + query);
	assert.equal(await page.getByRole('button', { name: 'Continue with passkey' }).isEnabled(), true);
});

test('cancellation never claims the account is missing and offers a retry', async (t) => {
	const page = await pageFor(t);
	await page.evaluate(() =>
		Object.defineProperty(navigator.credentials, 'get', {
			value: async () => {
				throw new DOMException('Browser-specific cancellation', 'NotAllowedError');
			}
		})
	);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: 'The passkey prompt was not completed.' }).waitFor();
	assert.equal(await page.getByRole('button', { name: 'Try again' }).isEnabled(), true);
	assert.ok(!(await page.locator('#status').innerText()).includes('registered'));
});

test('expired challenges do not auto-reload or loop', async (t) => {
	const page = await pageFor(t);
	await page.route('**/webauthn/assert/finish', (route) =>
		failure(route, 'unknown or expired ceremony')
	);
	let navigations = 0;
	page.on('framenavigated', () => navigations++);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: 'This attempt has expired.' }).waitFor();
	assert.equal(navigations, 0);
	assert.equal(await page.getByRole('button', { name: 'Try again' }).isEnabled(), true);
});

test('server and network failures guide retry without suggesting a new account', async (t) => {
	const page = await pageFor(t);
	await page.route('**/webauthn/assert/finish', (route) =>
		failure(route, 'database unavailable', 503)
	);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	assert.ok(
		(await page.locator('#status').innerText()).includes('do not need to create another account')
	);
	await page.unroute('**/webauthn/assert/finish');
	await page.route('**/webauthn/assert/finish', (route) => route.abort('failed'));
	await page.getByRole('button', { name: 'Try again' }).click();
	await page.getByRole('heading', { name: "We couldn't reach IdentiKey." }).waitFor();
});

test('error text is escaped, and mobile layout has no horizontal overflow', async (t) => {
	const page = await pageFor(t, 'login', { width: 390, height: 844 });
	const payload = '<img src=x onerror="window.injected=true">';
	await page.route('**/webauthn/assert/finish', (route) => failure(route, payload));
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByText('Technical details', { exact: true }).click();
	assert.equal(await page.evaluate(() => window.injected), undefined);
	assert.equal(await page.locator('#technical-message img').count(), 0);
	assert.equal(
		JSON.parse(await page.locator('#technical-message').textContent()).error_description,
		payload
	);
	assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
});

test('signup cancellation retries the same pending account and preserves the app context', async (t) => {
	const page = await pageFor(t, 'signup');
	let accounts = 0;
	let refreshed = 0;
	const pk = { challenge: 'YWJj', user: { id: 'YWJj' } };
	await page.route('**/signup', (route) => {
		accounts++;
		return route.fulfill({ json: { xid: 'test-account', session: 'first', publicKey: pk } });
	});
	await page.route('**/webauthn/register/begin', (route) => {
		refreshed++;
		assert.equal(route.request().postDataJSON().xid, 'test-account');
		return route.fulfill({ json: { session: 'second', publicKey: pk } });
	});
	await page.evaluate(() =>
		Object.defineProperty(navigator.credentials, 'create', {
			value: async () => {
				throw new DOMException('Cancelled', 'NotAllowedError');
			}
		})
	);
	await page.getByRole('button', { name: 'Create account and add a passkey' }).click();
	await page.getByRole('heading', { name: 'Passkey setup was not completed.' }).waitFor();
	await page.getByRole('button', { name: 'Try saving a passkey again' }).click();
	await page.getByRole('heading', { name: 'Passkey setup was not completed.' }).waitFor();
	assert.equal(accounts, 1);
	assert.equal(refreshed, 1);
	assert.equal(
		new URL(await page.locator('#back').getAttribute('href'), origin).search,
		'?' + query
	);
});

test('unsupported browsers get an explanation rather than a broken button', async (t) => {
	const page = await pageFor(t);
	await page.addInitScript(() =>
		Object.defineProperty(window, 'PublicKeyCredential', { value: undefined })
	);
	await page.reload();
	await page
		.getByRole('heading', {
			name: 'Passkeys are not available in this browser or on this address.'
		})
		.waitFor();
	assert.equal(
		await page.getByRole('button', { name: 'Continue with passkey' }).isDisabled(),
		true
	);
});

const src = (name) =>
	readFileSync(new URL(`../../crates/identikey-server/src/${name}`, import.meta.url), 'utf8');
const devicePage = `<!doctype html><body><h1>Sign in</h1>
<div id="status" hidden tabindex="-1"><h2 id="status-title"></h2><p id="status-description"></p>
<button type="button" id="copy-report" hidden>Copy diagnostics</button><p id="copy-result"></p></div>
<button id="go">Approve</button><button id="deny">Cancel</button>
<details id="technical" hidden><summary>Technical details</summary><pre id="technical-message"></pre></details>
<div id="local-notice" hidden></div>
<script type="application/json" id="device">{"user_code":"ABCD-EFGH"}</script>
<script>${src('pages-common.js')}\n${src('pages-device.js')}</script></body>`;

async function devicePageFor(t) {
	const page = await pageFor(t);
	await page.route('**/device?*', (route) =>
		route.fulfill({ contentType: 'text/html', body: devicePage })
	);
	await page.goto(`${origin}/device?user_code=ABCD-EFGH`);
	return page;
}
const stubClipboard = (page, fail = false) =>
	page.evaluate((fail) => {
		window.copied = [];
		Object.defineProperty(navigator, 'clipboard', {
			configurable: true,
			value: {
				writeText: async (text) => {
					if (fail) throw new Error('denied');
					window.copied.push(text);
				}
			}
		});
	}, fail);
const countPrompts = (page) =>
	page.evaluate(() => {
		window.prompts = 0;
		for (const name of ['get', 'create'])
			Object.defineProperty(navigator.credentials, name, {
				configurable: true,
				value: async () => {
					window.prompts++;
					return { id: 'SECRET-CRED-ID', rawId: new ArrayBuffer(4), type: 'public-key', response: {} };
				}
			});
	});
const copied = async (page) => {
	await page.getByRole('button', { name: 'Copy diagnostics' }).click();
	await page.waitForFunction(() => window.copied.length === 1);
	return JSON.parse(await page.evaluate(() => window.copied[0]));
};

test('copy report has the error name and omits credential ids', async (t) => {
	const page = await pageFor(t);
	await stubClipboard(page);
	await page.route('**/webauthn/assert/finish', (route) => failure(route, 'credential not found'));
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: "That passkey isn't registered here." }).waitFor();
	const raw = await page.evaluate(
		() => (window.__r = null) ?? document.getElementById('status').innerText
	);
	assert.ok(raw.includes('Copy diagnostics'));
	const report = await copied(page);
	assert.equal(report.stage, 'finish');
	assert.equal(report.error_name, 'ResponseError');
	assert.equal(report.server_error, 'invalid_request');
	assert.equal(report.http_status, 400);
	assert.equal(report.secure_context, true);
	assert.equal(report.public_key_credential, true);
	assert.equal(report.navigator_credentials, true);
	const text = JSON.stringify(report);
	assert.ok(!text.includes('test'.repeat(1) + '"'));
	for (const banned of ['session', 'challenge', 'rawId', 'credential_id', 'email', 'cookie'])
		assert.ok(!(banned in report), banned);
});

test('failed clipboard write keeps the status and says the copy did not happen', async (t) => {
	const page = await pageFor(t);
	await stubClipboard(page, true);
	await page.route('**/webauthn/assert/finish', (route) => failure(route, 'x', 503));
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	await page.getByRole('button', { name: 'Copy diagnostics' }).click();
	await page.getByText('The copy did not happen', { exact: false }).waitFor();
	assert.equal(await page.locator('#status').isVisible(), true);
	assert.ok(!(await page.locator('#copy-result').innerText()).includes('copied'));
});

test('unsupported browser report uses the support stage', async (t) => {
	const page = await pageFor(t);
	await page.addInitScript(() =>
		Object.defineProperty(window, 'PublicKeyCredential', { value: undefined })
	);
	await page.reload();
	await stubClipboard(page);
	const report = await copied(page);
	assert.equal(report.stage, 'support');
	assert.equal(report.public_key_credential, false);
	assert.equal(report.error_name, 'NotSupportedError');
});

test('the five outcomes have distinct headings and the prompt wording is ambiguous', async (t) => {
	const titles = new Set();
	const page = await pageFor(t);
	const title = () => page.locator('#status-title').innerText();
	await page.evaluate(() =>
		Object.defineProperty(navigator.credentials, 'get', {
			configurable: true,
			value: async () => {
				throw new DOMException('x', 'AbortError');
			}
		})
	);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.locator('#status-title').filter({ hasText: 'not completed' }).waitFor();
	const body = await page.locator('#status').innerText();
	assert.ok(body.includes('does not mean your account is missing'));
	const claims = body.toLowerCase().replace('does not mean your account is missing', '');
	for (const bad of ['cancel', 'not installed', 'missing', 'no account', "isn't registered"])
		assert.ok(!claims.includes(bad), bad);
	titles.add(await title());
	await page.evaluate(() =>
		Object.defineProperty(navigator.credentials, 'get', {
			configurable: true,
			value: async () => ({ id: 'a', rawId: new ArrayBuffer(4), type: 'public-key', response: {} })
		})
	);
	for (const [message, status] of [
		['credential not found', 400],
		['unknown or expired ceremony', 400],
		['down', 503]
	]) {
		await page.unroute('**/webauthn/assert/finish').catch(() => {});
		await page.route('**/webauthn/assert/finish', (route) => failure(route, message, status));
		await page.getByRole('button', { name: /Try/ }).click();
		await page.waitForFunction(
			(old) => document.getElementById('status-title').textContent !== old,
			await title()
		);
		titles.add(await title());
	}
	// the fifth, unavailable WebAuthn, is covered by the unsupported-browser test
	assert.equal(titles.size, 4);
});

test('prepare failures do not open the prompt (login renewal, signup, device)', async (t) => {
	// login: a retry renews options first
	let page = await pageFor(t);
	await stubClipboard(page);
	await page.evaluate(() =>
		Object.defineProperty(navigator.credentials, 'get', {
			configurable: true,
			value: async () => {
				throw new DOMException('x', 'NotAllowedError');
			}
		})
	);
	await page.getByRole('button', { name: 'Continue with passkey' }).click();
	await page.locator('#status-title').filter({ hasText: 'not completed' }).waitFor();
	await countPrompts(page);
	await page.route('**/authorize/passkey?*', (route) => failure(route, 'down', 503));
	await page.getByRole('button', { name: 'Try again' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	assert.equal(await page.evaluate(() => window.prompts), 0);
	assert.equal((await copied(page)).stage, 'prepare');

	// signup
	page = await pageFor(t, 'signup');
	await stubClipboard(page);
	await countPrompts(page);
	await page.route('**/signup', (route) => failure(route, 'down', 503));
	await page.getByRole('button', { name: 'Create account and add a passkey' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	assert.equal(await page.evaluate(() => window.prompts), 0);
	assert.equal((await copied(page)).stage, 'prepare');

	// device approval
	page = await devicePageFor(t);
	await stubClipboard(page);
	await countPrompts(page);
	await page.route('**/device/assert/begin', (route) => failure(route, 'down', 503));
	await page.getByRole('button', { name: 'Approve' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	assert.equal(await page.evaluate(() => window.prompts), 0);
	assert.equal((await copied(page)).stage, 'prepare');
});

test('a failed device denial copies the deny stage', async (t) => {
	const page = await devicePageFor(t);
	await stubClipboard(page);
	await page.route('**/device/deny', (route) => failure(route, 'down', 503));
	await page.getByRole('button', { name: 'Cancel' }).click();
	await page.getByRole('heading', { name: 'IdentiKey is temporarily unavailable.' }).waitFor();
	assert.equal((await copied(page)).stage, 'deny');
});

// Source-backed fixtures exercise each shipped page without requiring a restart
// of the local OP after editing its embedded scripts.
async function signalPageFor(t, kind, behavior = 'ok', rpId = 'auth.identikey.me') {
	const page = await pageFor(t);
	const calls = [];
	await page.exposeFunction('recordSignal', (method, payload) => calls.push({ method, payload }));
	await page.addInitScript(({ behavior }) => {
		for (const method of ['signalAllAcceptedCredentials', 'signalUnknownCredential']) {
			Object.defineProperty(PublicKeyCredential, method, {
				configurable: true,
				value: behavior === 'missing' ? undefined : (payload) => {
					if (payload?.userId instanceof Uint8Array) {
						payload = { ...payload, userId: Array.from(payload.userId) };
					}
					window.recordSignal(method, payload);
					if (behavior === 'throw') throw new Error('provider threw');
					if (behavior === 'reject') return Promise.reject(new Error('provider rejected'));
					if (behavior === 'pending') return new Promise(() => {});
					return Promise.resolve();
				}
			});
		}
	}, { behavior });
	const publicKey = { challenge: 'YWJj', rpId, rp: { id: rpId }, user: { id: 'aGFuZGxl' } };
	const options = { session: 'signal-test', xid: 'test-xid', publicKey };
	const html = devicePage
		.replace('<script>', `<a id="signup"></a><a id="back"></a><details id="passkey-help"></details>
<script type="application/json" id="ceremony">${JSON.stringify(options)}</script><script>`)
		.replace(src('pages-device.js'), src(`pages-${kind}.js`));
	await page.route('**/signal-harness*', (route) => route.fulfill({ contentType: 'text/html', body: html }));
	await page.route('**/signup', (route) => route.fulfill({ json: options }));
	await page.route('**/device/assert/begin', (route) => route.fulfill({ json: options }));
	await page.route('**/signal-complete', (route) => route.fulfill({ contentType: 'text/html', body: '<h1>Complete</h1>' }));
	await page.goto(`${origin}/signal-harness`);
	return { page, calls, rpId };
}

for (const kind of ['login', 'signup', 'device']) {
	for (const behavior of ['ok', 'missing', 'throw', 'reject', 'pending']) {
		test(`signal ${kind}: ${behavior} provider still completes after server accept`, async (t) => {
			const { page, calls, rpId } = await signalPageFor(t, kind, behavior);
			const result = {
				redirect: '/signal-complete', next: '/signal-complete', approved: true,
				signal_user_id: 'aGFuZGxl', signal_credential_ids: ['test', 'other']
			};
			const endpoint = kind === 'signup' ? '**/webauthn/register/finish' :
				kind === 'device' ? '**/device/assert/finish' : '**/webauthn/assert/finish';
			await page.route(endpoint, async (route) => {
				assert.equal(calls.length, 0, 'no signal before server acceptance');
				assert.equal(route.request().postDataJSON().credential.id, 'test');
				await route.fulfill({ json: result });
			});
			await page.locator('#go').click();
			await page.getByRole('heading', { name: kind === 'device' ? 'Approved' : 'Complete', exact: true }).waitFor();
			if (behavior === 'missing') assert.deepEqual(calls, []);
			else {
				await page.waitForTimeout(20);
				assert.deepEqual(calls, [{ method: 'signalAllAcceptedCredentials', payload: {
					rpId, userId: [104, 97, 110, 100, 108, 101], allAcceptedCredentialIds: ['test', 'other']
				} }]);
			}
		});
	}
	for (const list of [undefined, []]) {
		test(`signal ${kind}: ${list ? 'empty' : 'missing'} list still completes without signaling`, async (t) => {
			const { page, calls } = await signalPageFor(t, kind);
			const endpoint = kind === 'signup' ? '**/webauthn/register/finish' :
				kind === 'device' ? '**/device/assert/finish' : '**/webauthn/assert/finish';
			await page.route(endpoint, (route) => route.fulfill({ json: {
				redirect: '/signal-complete', next: '/signal-complete', approved: true,
				signal_user_id: list ? 'aGFuZGxl' : undefined, signal_credential_ids: list
			} }));
			await page.locator('#go').click();
			await page.getByRole('heading', { name: kind === 'device' ? 'Approved' : 'Complete', exact: true }).waitFor();
			assert.deepEqual(calls, []);
		});
	}
}
for (const kind of ['login', 'device']) {
	for (const [error, rpId, signals] of [
		['credential not found', 'auth.identikey.me', true], // includes a revoked row
		['credential not found', 'localhost', false],
		['credential belongs to another account', 'auth.identikey.me', false],
		['unknown or expired ceremony', 'auth.identikey.me', false],
		['cancel', 'auth.identikey.me', false]
	]) {
		test(`signal ${kind}: ${error} on ${rpId}`, async (t) => {
			const { page, calls } = await signalPageFor(t, kind, 'ok', rpId);
			if (error === 'cancel') {
				await page.evaluate(() => Object.defineProperty(navigator.credentials, 'get', {
					value: async () => { throw new DOMException('Cancelled', 'NotAllowedError'); }
				}));
			} else {
				await page.route(kind === 'device' ? '**/device/assert/finish' : '**/webauthn/assert/finish',
					(route) => failure(route, error));
			}
			await page.locator('#go').click();
			await page.locator('#status').waitFor({ state: 'visible' });
			if (signals) {
				await page.waitForFunction(() => document.getElementById('go').disabled === false);
				assert.deepEqual(calls, [{ method: 'signalUnknownCredential', payload: { rpId, credentialId: 'test' } }]);
			} else assert.deepEqual(calls, []);
			assert.equal(await page.locator('#technical-message').isHidden(), true);
		});
	}
}


test('signal signup with app context still navigates when the provider never settles', async (t) => {
	const { page, calls } = await signalPageFor(t, 'signup', 'pending');
	await page.goto(`${origin}/signal-harness?${query}`);
	await page.route('**/webauthn/register/finish', (route) => route.fulfill({ json: {
		next: '/account', signal_user_id: 'aGFuZGxl', signal_credential_ids: ['test']
	} }));
	await page.route('**/authorize/passkey?*', (route) => route.fulfill({
		contentType: 'text/html', body: '<h1>Complete</h1>'
	}));
	await page.locator('#go').click();
	await page.getByRole('heading', { name: 'Complete', exact: true }).waitFor();
	assert.equal(new URL(page.url()).hash, '#passkey-saved');
	assert.equal(new URL(page.url()).search, '?' + query);
	assert.equal(calls.length, 1);
	assert.equal(calls[0].method, 'signalAllAcceptedCredentials');
});
