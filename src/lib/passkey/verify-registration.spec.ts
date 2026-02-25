import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockChallenge = {
	id: 'challenge-uuid-1',
	userId: 'user-123',
	challenge: 'dGVzdC1jaGFsbGVuZ2U',
	type: 'registration',
	expiresAt: new Date(Date.now() + 300_000),
	createdAt: new Date()
};

const mockPublicKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

const mockRegistrationInfo = {
	fmt: 'none' as const,
	aaguid: '00000000-0000-0000-0000-000000000000',
	credential: {
		id: 'credential-id-abc',
		publicKey: mockPublicKey,
		counter: 0,
		transports: ['internal'] as string[]
	},
	credentialType: 'public-key' as const,
	attestationObject: new Uint8Array([0]),
	userVerified: true,
	credentialDeviceType: 'multiDevice' as const,
	credentialBackedUp: true,
	origin: 'http://localhost:5173'
};

vi.mock('$lib/server/challenges', () => ({
	getChallengeByValue: vi.fn(),
	deleteChallengeByValue: vi.fn().mockResolvedValue(undefined)
}));

vi.mock('@simplewebauthn/server', () => ({
	verifyRegistrationResponse: vi.fn()
}));

vi.mock('./credential-store', () => ({
	storePasskeyCredential: vi.fn().mockResolvedValue({
		id: 'stored-uuid',
		userId: 'user-123',
		credentialId: 'credential-id-abc',
		publicKey: 'AQIDBAUGB/g=',
		counter: 0,
		transports: JSON.stringify(['internal']),
		deviceType: 'multiDevice',
		backedUp: true,
		createdAt: new Date(),
		lastUsedAt: null
	})
}));

import { verifyAndStorePasskey } from './verify-registration';
import { getChallengeByValue, deleteChallengeByValue } from '$lib/server/challenges';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { storePasskeyCredential } from './credential-store';
import { PasskeyError, PasskeyErrorCode } from './errors';

const mockedGetChallenge = vi.mocked(getChallengeByValue);
const mockedDeleteChallenge = vi.mocked(deleteChallengeByValue);
const mockedVerify = vi.mocked(verifyRegistrationResponse);
const mockedStore = vi.mocked(storePasskeyCredential);

const baseParams = {
	attestationResponse: {
		id: 'credential-id-abc',
		rawId: 'credential-id-abc',
		type: 'public-key' as const,
		response: {
			clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
			attestationObject: 'o2NmbXRkbm9uZQ'
		},
		clientExtensionResults: {},
		authenticatorAttachment: 'platform' as const
	},
	challenge: 'dGVzdC1jaGFsbGVuZ2U',
	userId: 'user-123'
};

beforeEach(() => {
	vi.clearAllMocks();
	process.env.WEBAUTHN_RP_ID = 'localhost';
	process.env.WEBAUTHN_RP_NAME = 'IdentiKey';
	process.env.WEBAUTHN_EXPECTED_ORIGIN = 'http://localhost:5173';
});

describe('verifyAndStorePasskey', () => {
	it('happy path: looks up challenge, verifies, stores credential, deletes challenge', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockResolvedValueOnce({
			verified: true,
			registrationInfo: mockRegistrationInfo
		});

		const result = await verifyAndStorePasskey(baseParams);

		expect(mockedGetChallenge).toHaveBeenCalledWith('dGVzdC1jaGFsbGVuZ2U');

		expect(mockedVerify).toHaveBeenCalledWith({
			response: baseParams.attestationResponse,
			expectedChallenge: 'dGVzdC1jaGFsbGVuZ2U',
			expectedOrigin: ['http://localhost:5173'],
			expectedRPID: 'localhost'
		});

		expect(mockedStore).toHaveBeenCalledWith({
			userId: 'user-123',
			credentialId: 'credential-id-abc',
			publicKey: Buffer.from(mockPublicKey).toString('base64'),
			counter: 0,
			transports: ['internal'],
			deviceType: 'multiDevice',
			backedUp: true
		});

		expect(mockedDeleteChallenge).toHaveBeenCalledWith('dGVzdC1jaGFsbGVuZ2U');

		expect(result).toEqual({
			credentialId: 'credential-id-abc',
			publicKey: Buffer.from(mockPublicKey).toString('base64'),
			counter: 0,
			transports: ['internal'],
			deviceType: 'multiDevice',
			backedUp: true,
			userId: 'user-123'
		});
	});

	it('throws CHALLENGE_NOT_FOUND when challenge is missing or expired', async () => {
		mockedGetChallenge.mockResolvedValueOnce(null);

		const err = await verifyAndStorePasskey(baseParams).catch((e) => e);
		expect(err).toBeInstanceOf(PasskeyError);
		expect(err.code).toBe(PasskeyErrorCode.CHALLENGE_NOT_FOUND);
		expect(mockedVerify).not.toHaveBeenCalled();
	});

	it('throws CHALLENGE_USER_MISMATCH when userId does not match', async () => {
		mockedGetChallenge.mockResolvedValueOnce({ ...mockChallenge, userId: 'other-user' });

		const err = await verifyAndStorePasskey(baseParams).catch((e) => e);
		expect(err).toBeInstanceOf(PasskeyError);
		expect(err.code).toBe(PasskeyErrorCode.CHALLENGE_USER_MISMATCH);
	});

	it('throws ATTESTATION_INVALID when verifyRegistrationResponse throws', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockRejectedValueOnce(new Error('Invalid attestation format'));

		const err = await verifyAndStorePasskey(baseParams).catch((e) => e);
		expect(err).toBeInstanceOf(PasskeyError);
		expect(err.code).toBe(PasskeyErrorCode.ATTESTATION_INVALID);
	});

	it('throws VERIFICATION_FAILED when verified is false', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockResolvedValueOnce({ verified: false });

		const err = await verifyAndStorePasskey(baseParams).catch((e) => e);
		expect(err).toBeInstanceOf(PasskeyError);
		expect(err.code).toBe(PasskeyErrorCode.VERIFICATION_FAILED);
	});

	it('throws STORAGE_FAILED when storePasskeyCredential fails', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockResolvedValueOnce({
			verified: true,
			registrationInfo: mockRegistrationInfo
		});
		mockedStore.mockRejectedValueOnce(new Error('unique constraint violation'));

		const err = await verifyAndStorePasskey(baseParams).catch((e) => e);
		expect(err).toBeInstanceOf(PasskeyError);
		expect(err.code).toBe(PasskeyErrorCode.STORAGE_FAILED);
		expect(mockedDeleteChallenge).not.toHaveBeenCalled();
	});

	it('challenge is not deleted on verification failure', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockRejectedValueOnce(new Error('bad attestation'));

		await expect(verifyAndStorePasskey(baseParams)).rejects.toThrow();
		expect(mockedDeleteChallenge).not.toHaveBeenCalled();
	});

	it('supports multiple origins from comma-separated env var', async () => {
		process.env.WEBAUTHN_EXPECTED_ORIGIN = 'https://connect.identikey.io, android:apk-key-hash:abc123';
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockResolvedValueOnce({
			verified: true,
			registrationInfo: mockRegistrationInfo
		});

		await verifyAndStorePasskey(baseParams);

		expect(mockedVerify).toHaveBeenCalledWith(
			expect.objectContaining({
				expectedOrigin: ['https://connect.identikey.io', 'android:apk-key-hash:abc123']
			})
		);
	});

	it('defaults to localhost:5173 when WEBAUTHN_EXPECTED_ORIGIN unset', async () => {
		delete process.env.WEBAUTHN_EXPECTED_ORIGIN;
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		mockedVerify.mockResolvedValueOnce({
			verified: true,
			registrationInfo: mockRegistrationInfo
		});

		await verifyAndStorePasskey(baseParams);

		expect(mockedVerify).toHaveBeenCalledWith(
			expect.objectContaining({
				expectedOrigin: ['http://localhost:5173']
			})
		);
	});

	it('handles credential with no transports', async () => {
		mockedGetChallenge.mockResolvedValueOnce(mockChallenge);
		const noTransportsInfo = {
			...mockRegistrationInfo,
			credential: { ...mockRegistrationInfo.credential, transports: undefined }
		};
		mockedVerify.mockResolvedValueOnce({
			verified: true,
			registrationInfo: noTransportsInfo
		});

		const result = await verifyAndStorePasskey(baseParams);

		expect(result.transports).toBeUndefined();
		expect(mockedStore).toHaveBeenCalledWith(
			expect.objectContaining({ transports: undefined })
		);
	});
});
