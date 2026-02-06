import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock jose before importing module under test
vi.mock('jose', () => ({
	createRemoteJWKSet: vi.fn(),
}));

import { createRemoteJWKSet } from 'jose';
import {
	getAppleJwkSet,
	getGoogleJwkSet,
	getProviderJwkSet,
	APPLE_JWKS_URI,
	GOOGLE_JWKS_URI,
	_resetProviderCache,
} from './provider-jwks';

const mockCreateRemoteJWKSet = vi.mocked(createRemoteJWKSet);

describe('Provider JWKS Service', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		_resetProviderCache();
		mockCreateRemoteJWKSet.mockReturnValue(vi.fn() as any);
	});

	describe('JWKS URIs', () => {
		it('should have correct Apple JWKS URI', () => {
			expect(APPLE_JWKS_URI).toBe('https://appleid.apple.com/auth/keys');
		});

		it('should have correct Google JWKS URI', () => {
			expect(GOOGLE_JWKS_URI).toBe('https://www.googleapis.com/oauth2/v3/certs');
		});
	});

	describe('getAppleJwkSet', () => {
		it('should call createRemoteJWKSet with Apple JWKS URL', () => {
			getAppleJwkSet();
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
				new URL(APPLE_JWKS_URI),
			);
		});

		it('should return a callable key function that delegates to createRemoteJWKSet', async () => {
			const mockKey = { type: 'mock-key' };
			const mockKeyFn = vi.fn().mockResolvedValue(mockKey);
			mockCreateRemoteJWKSet.mockReturnValue(mockKeyFn as any);

			const result = getAppleJwkSet();
			expect(typeof result).toBe('function');
			const key = await result({} as any, {} as any);
			expect(key).toBe(mockKey);
			expect(mockKeyFn).toHaveBeenCalled();
		});

		it('should cache the key function across calls', () => {
			const mockKeyFn = vi.fn();
			mockCreateRemoteJWKSet.mockReturnValue(mockKeyFn as any);

			const first = getAppleJwkSet();
			const second = getAppleJwkSet();
			expect(first).toBe(second);
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledTimes(1);
		});
	});

	describe('getGoogleJwkSet', () => {
		it('should call createRemoteJWKSet with Google JWKS URL', () => {
			getGoogleJwkSet();
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
				new URL(GOOGLE_JWKS_URI),
			);
		});

		it('should return a callable key function that delegates to createRemoteJWKSet', async () => {
			const mockKey = { type: 'mock-key' };
			const mockKeyFn = vi.fn().mockResolvedValue(mockKey);
			mockCreateRemoteJWKSet.mockReturnValue(mockKeyFn as any);

			const result = getGoogleJwkSet();
			expect(typeof result).toBe('function');
			const key = await result({} as any, {} as any);
			expect(key).toBe(mockKey);
			expect(mockKeyFn).toHaveBeenCalled();
		});

		it('should cache the key function across calls', () => {
			const mockKeyFn = vi.fn();
			mockCreateRemoteJWKSet.mockReturnValue(mockKeyFn as any);

			const first = getGoogleJwkSet();
			const second = getGoogleJwkSet();
			expect(first).toBe(second);
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledTimes(1);
		});
	});

	describe('error wrapping', () => {
		it('should wrap fetch errors from key function as ProviderJwksError', async () => {
			const { ProviderJwksError } = await import('../errors');
			const fetchError = new Error('Network error');
			const failingKeyFn = vi.fn().mockRejectedValue(fetchError);
			mockCreateRemoteJWKSet.mockReturnValue(failingKeyFn as any);

			const keyFn = getAppleJwkSet();
			await expect(keyFn({} as any, {} as any)).rejects.toThrow(ProviderJwksError);
		});

		it('should include original error as cause', async () => {
			const fetchError = new Error('Network error');
			const failingKeyFn = vi.fn().mockRejectedValue(fetchError);
			mockCreateRemoteJWKSet.mockReturnValue(failingKeyFn as any);

			const keyFn = getAppleJwkSet();
			try {
				await keyFn({} as any, {} as any);
				expect.unreachable();
			} catch (err: any) {
				expect(err.cause).toBe(fetchError);
			}
		});

		it('should include provider name in error message', async () => {
			const failingKeyFn = vi.fn().mockRejectedValue(new Error('fail'));
			mockCreateRemoteJWKSet.mockReturnValue(failingKeyFn as any);

			const keyFn = getGoogleJwkSet();
			await expect(keyFn({} as any, {} as any)).rejects.toThrow(/google/i);
		});
	});

	describe('getProviderJwkSet', () => {
		it('should return Apple key function for "apple" provider', () => {
			const result = getProviderJwkSet('apple');
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
				new URL(APPLE_JWKS_URI),
			);
			expect(result).toBeDefined();
		});

		it('should return Google key function for "google" provider', () => {
			const result = getProviderJwkSet('google');
			expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
				new URL(GOOGLE_JWKS_URI),
			);
			expect(result).toBeDefined();
		});

		it('should throw ProviderJwksError for unknown provider', async () => {
			const { ProviderJwksError } = await import('../errors');
			expect(() => getProviderJwkSet('unknown' as any)).toThrow(ProviderJwksError);
		});
	});
});
