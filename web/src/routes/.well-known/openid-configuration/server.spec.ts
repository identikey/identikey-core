import { describe, expect, it, vi, beforeEach } from 'vitest';

describe('GET /.well-known/openid-configuration', () => {
	const ORIGINAL_ENV = { ...process.env };

	beforeEach(() => {
		vi.resetModules();
		process.env = { ...ORIGINAL_ENV };
	});

	it('returns 200 with JSON body', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);

		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toBe('application/json');
	});

	it('returns required OIDC discovery fields', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);
		const body = await response.json();

		expect(body.issuer).toBe('https://connect.identikey.io');
		expect(body.jwks_uri).toBe('https://connect.identikey.io/.well-known/jwks.json');
		expect(body.token_endpoint).toBe('https://connect.identikey.io/api/token/refresh');
		expect(body.introspection_endpoint).toBe('https://connect.identikey.io/api/introspect');
	});

	it('jwks_uri ends with /.well-known/jwks.json', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);
		const body = await response.json();

		expect(body.jwks_uri).toMatch(/\/\.well-known\/jwks\.json$/);
	});

	it('strips trailing slash from issuer', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io/';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);
		const body = await response.json();

		expect(body.issuer).toBe('https://connect.identikey.io');
		expect(body.jwks_uri).toBe('https://connect.identikey.io/.well-known/jwks.json');
	});

	it('falls back to request url.origin when IDENTIKEY_ISSUER not set', async () => {
		delete process.env.IDENTIKEY_ISSUER;
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://my-app.example.com/.well-known/openid-configuration') } as any);
		const body = await response.json();

		expect(body.issuer).toBe('https://my-app.example.com');
		expect(body.jwks_uri).toBe('https://my-app.example.com/.well-known/jwks.json');
	});

	it('returns Cache-Control header with public and max-age', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);

		const cacheControl = response.headers.get('Cache-Control');
		expect(cacheControl).toBeDefined();
		expect(cacheControl).toContain('public');
		expect(cacheControl).toMatch(/max-age=\d+/);
	});

	it('works without signing key initialized (no 503)', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		delete process.env.IDENTIKEY_SIGNING_KEY;
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);

		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.issuer).toBeDefined();
	});

	it('includes id_token_signing_alg_values_supported with EdDSA', async () => {
		process.env.IDENTIKEY_ISSUER = 'https://connect.identikey.io';
		const { GET } = await import('./+server');
		const response = await GET({ url: new URL('https://connect.identikey.io/.well-known/openid-configuration') } as any);
		const body = await response.json();

		expect(body.id_token_signing_alg_values_supported).toEqual(['EdDSA']);
	});
});
