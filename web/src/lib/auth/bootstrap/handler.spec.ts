import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { getBootstrapHandler } from './handler';
import type { ProvisionResult } from './provision';

const APPLE_TOKEN = 'apple-id-token';
const GOOGLE_TOKEN = 'google-id-token';

const mockProvisionResult = (
	overrides: Partial<ProvisionResult> = {}
): ProvisionResult => ({
	userId: 'user-123',
	isNewUser: true,
	email: 'u@example.com',
	provider: 'apple',
	...overrides
});

vi.mock('../apple', () => ({ verifyAppleToken: vi.fn() }));
vi.mock('../google', () => ({ verifyGoogleToken: vi.fn() }));
vi.mock('./provision', () => ({ provisionUser: vi.fn() }));

beforeEach(() => {
	vi.clearAllMocks();
});

describe('getBootstrapHandler', () => {
	it('returns handler for apple', () => {
		const handler = getBootstrapHandler('apple');
		expect(handler).toBeDefined();
		expect(typeof handler.verifyAndProvision).toBe('function');
	});

	it('returns handler for google', () => {
		const handler = getBootstrapHandler('google');
		expect(handler).toBeDefined();
		expect(typeof handler.verifyAndProvision).toBe('function');
	});

	it('returns same handler instance for same provider', () => {
		expect(getBootstrapHandler('apple')).toBe(getBootstrapHandler('apple'));
		expect(getBootstrapHandler('google')).toBe(getBootstrapHandler('google'));
	});
});

describe('Apple handler — verifyAndProvision', () => {
	it('calls verifyAppleToken then provisionUser and returns ProvisionResult', async () => {
		const { verifyAppleToken } = await import('../apple');
		const { provisionUser } = await import('./provision');
		(verifyAppleToken as Mock).mockResolvedValue({
			sub: 'apple-sub-001',
			email: 'u@example.com',
			email_verified: true
		});
		(provisionUser as Mock).mockResolvedValue(
			mockProvisionResult({ provider: 'apple', userId: 'kc-1' })
		);

		const handler = getBootstrapHandler('apple');
		const result = await handler.verifyAndProvision(APPLE_TOKEN);

		expect(verifyAppleToken).toHaveBeenCalledTimes(1);
		expect(verifyAppleToken).toHaveBeenCalledWith(APPLE_TOKEN);
		expect(provisionUser).toHaveBeenCalledTimes(1);
		expect(provisionUser).toHaveBeenCalledWith('apple', {
			sub: 'apple-sub-001',
			email: 'u@example.com',
			email_verified: true
		});
		expect(result).toEqual(
			expect.objectContaining({
				userId: 'kc-1',
				provider: 'apple'
			})
		);
	});

	it('calls provisionUser only after verifyAppleToken succeeds', async () => {
		const { verifyAppleToken } = await import('../apple');
		const { provisionUser } = await import('./provision');
		(verifyAppleToken as Mock).mockResolvedValue({ sub: 'sub' });
		(provisionUser as Mock).mockResolvedValue(mockProvisionResult());

		await getBootstrapHandler('apple').verifyAndProvision(APPLE_TOKEN);

		expect(verifyAppleToken).toHaveBeenCalledBefore(provisionUser as Mock);
	});

	it('does not call provisionUser when verifyAppleToken throws', async () => {
		const { verifyAppleToken } = await import('../apple');
		const { provisionUser } = await import('./provision');
		const tokenError = new Error('Invalid token');
		(verifyAppleToken as Mock).mockRejectedValue(tokenError);

		await expect(
			getBootstrapHandler('apple').verifyAndProvision(APPLE_TOKEN)
		).rejects.toThrow('Invalid token');

		expect(provisionUser).not.toHaveBeenCalled();
	});

	it('propagates provisionUser errors', async () => {
		const { verifyAppleToken } = await import('../apple');
		const { provisionUser } = await import('./provision');
		(verifyAppleToken as Mock).mockResolvedValue({ sub: 'sub' });
		const provisionError = new Error('Provision failed');
		(provisionUser as Mock).mockRejectedValue(provisionError);

		await expect(
			getBootstrapHandler('apple').verifyAndProvision(APPLE_TOKEN)
		).rejects.toThrow('Provision failed');
	});
});

describe('Google handler — verifyAndProvision', () => {
	it('calls verifyGoogleToken then provisionUser and returns ProvisionResult', async () => {
		const { verifyGoogleToken } = await import('../google');
		const { provisionUser } = await import('./provision');
		(verifyGoogleToken as Mock).mockResolvedValue({
			sub: 'google-sub-999',
			email: 'g@gmail.com',
			name: 'Test User'
		});
		(provisionUser as Mock).mockResolvedValue(
			mockProvisionResult({ provider: 'google', userId: 'kc-2' })
		);

		const handler = getBootstrapHandler('google');
		const result = await handler.verifyAndProvision(GOOGLE_TOKEN);

		expect(verifyGoogleToken).toHaveBeenCalledTimes(1);
		expect(verifyGoogleToken).toHaveBeenCalledWith(GOOGLE_TOKEN);
		expect(provisionUser).toHaveBeenCalledTimes(1);
		expect(provisionUser).toHaveBeenCalledWith('google', {
			sub: 'google-sub-999',
			email: 'g@gmail.com',
			name: 'Test User'
		});
		expect(result).toEqual(
			expect.objectContaining({
				userId: 'kc-2',
				provider: 'google'
			})
		);
	});

	it('does not call provisionUser when verifyGoogleToken throws', async () => {
		const { verifyGoogleToken } = await import('../google');
		const { provisionUser } = await import('./provision');
		(verifyGoogleToken as Mock).mockRejectedValue(new Error('Bad token'));

		await expect(
			getBootstrapHandler('google').verifyAndProvision(GOOGLE_TOKEN)
		).rejects.toThrow('Bad token');

		expect(provisionUser).not.toHaveBeenCalled();
	});

	it('propagates provisionUser errors', async () => {
		const { verifyGoogleToken } = await import('../google');
		const { provisionUser } = await import('./provision');
		(verifyGoogleToken as Mock).mockResolvedValue({ sub: 'sub' });
		(provisionUser as Mock).mockRejectedValue(new Error('Keycloak down'));

		await expect(
			getBootstrapHandler('google').verifyAndProvision(GOOGLE_TOKEN)
		).rejects.toThrow('Keycloak down');
	});
});
