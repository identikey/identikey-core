import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';

vi.mock('$lib/auth/jwt', () => ({
	getSigningKey: vi.fn(),
	getPublicKeyJwk: vi.fn()
}));

const { getSigningKey, getPublicKeyJwk } = await import('$lib/auth/jwt');

describe('GET /.well-known/jwks.json', () => {
	let mockKeyPair: { privateKey: CryptoKey; publicKey: CryptoKey; kid: string };
	let mockPublicJwk: Record<string, string>;

	beforeEach(async () => {
		vi.clearAllMocks();
		const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
			crv: 'Ed25519',
			extractable: true
		});
		const pubJwk = await exportJWK(publicKey);
		const kid = await calculateJwkThumbprint(pubJwk, 'sha256');

		mockKeyPair = { privateKey, publicKey, kid } as unknown as typeof mockKeyPair;
		mockPublicJwk = {
			kty: 'OKP',
			crv: 'Ed25519',
			x: pubJwk.x!,
			kid,
			use: 'sig',
			alg: 'EdDSA'
		};
	});

	it('returns 200 with JWKS body containing keys array', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockReturnValue(mockKeyPair);
		(getPublicKeyJwk as ReturnType<typeof vi.fn>).mockResolvedValue(mockPublicJwk);

		const { GET } = await import('./+server');
		const response = await GET();

		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toHaveProperty('keys');
		expect(Array.isArray(body.keys)).toBe(true);
		expect(body.keys).toHaveLength(1);
	});

	it('returns JWK with required fields: kid, kty, crv, x, use, alg', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockReturnValue(mockKeyPair);
		(getPublicKeyJwk as ReturnType<typeof vi.fn>).mockResolvedValue(mockPublicJwk);

		const { GET } = await import('./+server');
		const response = await GET();
		const body = await response.json();
		const jwk = body.keys[0];

		expect(jwk.kid).toBe(mockKeyPair.kid);
		expect(jwk.kty).toBe('OKP');
		expect(jwk.crv).toBe('Ed25519');
		expect(jwk.x).toBeDefined();
		expect(jwk.use).toBe('sig');
		expect(jwk.alg).toBe('EdDSA');
	});

	it('does not include private key material (d field)', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockReturnValue(mockKeyPair);
		(getPublicKeyJwk as ReturnType<typeof vi.fn>).mockResolvedValue(mockPublicJwk);

		const { GET } = await import('./+server');
		const response = await GET();
		const body = await response.json();
		const jwk = body.keys[0];

		expect(jwk.d).toBeUndefined();
	});

	it('returns Content-Type application/json', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockReturnValue(mockKeyPair);
		(getPublicKeyJwk as ReturnType<typeof vi.fn>).mockResolvedValue(mockPublicJwk);

		const { GET } = await import('./+server');
		const response = await GET();

		expect(response.headers.get('Content-Type')).toBe('application/json');
	});

	it('returns Cache-Control header with max-age', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockReturnValue(mockKeyPair);
		(getPublicKeyJwk as ReturnType<typeof vi.fn>).mockResolvedValue(mockPublicJwk);

		const { GET } = await import('./+server');
		const response = await GET();

		const cacheControl = response.headers.get('Cache-Control');
		expect(cacheControl).toBeDefined();
		expect(cacheControl).toContain('public');
		expect(cacheControl).toMatch(/max-age=\d+/);
	});

	it('returns 503 when signing key is not initialized', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error('Signing key not initialized');
		});

		const { GET } = await import('./+server');
		const response = await GET();

		expect(response.status).toBe(503);
	});

	it('returns minimal body on 503', async () => {
		(getSigningKey as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error('Signing key not initialized');
		});

		const { GET } = await import('./+server');
		const response = await GET();
		const body = await response.json();

		expect(body).toHaveProperty('error');
		expect(response.status).toBe(503);
	});
});
