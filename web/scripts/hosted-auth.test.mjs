import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
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
	await page.getByRole('heading', { name: 'No passkey was selected.' }).waitFor();
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
