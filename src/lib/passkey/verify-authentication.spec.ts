import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockKnownUserChallenge = {
	id: 'challenge-uuid-1',
	userId: 'user-123',
	challenge: 'dGVzdC1jaGFsbGVuZ2U',
	type: 'authentication',
	expiresAt: new Date(Date.now() + 300_000),
	createdAt: new Date()
};

const mockDiscoverableChallenge = {
	...mockKnownUserChallenge,
	id: 'challenge-uuid-2',
	userId: null
};

// 'AQIDBAUGBwg=' is base64 for [1,2,3,4,5,6,7,8] — the round-trip the impl must perform.
const mockStoredCredential = {
	id: 'stored-uuid',
	userId: 'user-123',
	credentialId: 'credential-id-abc',
	publicKey: 'AQIDBAUGBwg=',
	counter: 5,
	transports: JSON.stringify(['internal', 'hybrid']),
	deviceType: 'multiDevice',
	backedUp: true,
	createdAt: new Date(),
	lastUsedAt: null
};

const mockAssertionResponse = {
	id: 'credential-id-abc',
	rawId: 'credential-id-abc',
	type: 'public-key' as const,
	clientExtensionResults: {},
	response: {
		clientDataJSON: 'e30',
		authenticatorData: 'YXV0aA',
		signature: 'c2ln',
		userHandle: 'dXNlci0xMjM'
	}
};

vi.mock('$lib/server/challenges', () => ({
	getChallengeByValue: vi.fn(),
	deleteChallengeByValue: vi.fn().mockResolvedValue(undefined)
}));

vi.mock('@simplewebauthn/server', () => ({
	verifyAuthenticationResponse: vi.fn()
}));

vi.mock('./credential-store', () => ({
	getPasskeyByCredentialId: vi.fn(),
	updatePasskeyCounter: vi.fn().mockResolvedValue(undefined)
}));

import { verifyAuthenticationAssertion } from './verify-authentication';
import { getChallengeByValue, deleteChallengeByValue } from '$lib/server/challenges';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getPasskeyByCredentialId, updatePasskeyCounter } from './credential-store';
import { PasskeyError, PasskeyErrorCode } from './errors';

const verified = (newCounter: number) => ({
	verified: true,
	authenticationInfo: {
		newCounter,
		credentialID: 'credential-id-abc',
		userVerified: true,
		credentialDeviceType: 'multiDevice' as const,
		credentialBackedUp: true,
		origin: 'http://localhost:5173',
		rpID: 'localhost'
	}
});

function callWith(challenge = mockKnownUserChallenge.challenge) {
	return verifyAuthenticationAssertion({
		assertionResponse: mockAssertionResponse,
		challenge
	});
}

describe('verifyAuthenticationAssertion', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.mocked(getChallengeByValue).mockResolvedValue(mockKnownUserChallenge as never);
		vi.mocked(getPasskeyByCredentialId).mockResolvedValue(mockStoredCredential as never);
		vi.mocked(verifyAuthenticationResponse).mockResolvedValue(verified(6) as never);
		vi.mocked(updatePasskeyCounter).mockResolvedValue(undefined as never);
		vi.mocked(deleteChallengeByValue).mockResolvedValue(undefined as never);
	});

	describe('known-user flow', () => {
		it('returns userId, credentialId and newCounter on success', async () => {
			await expect(callWith()).resolves.toEqual({
				userId: 'user-123',
				credentialId: 'credential-id-abc',
				newCounter: 6
			});
		});

		it('looks the credential up by the id from the assertion response', async () => {
			await callWith();
			expect(getPasskeyByCredentialId).toHaveBeenCalledWith('credential-id-abc');
		});

		it('persists the new counter for replay protection', async () => {
			await callWith();
			expect(updatePasskeyCounter).toHaveBeenCalledWith('credential-id-abc', 6);
		});

		it('deletes the used challenge', async () => {
			await callWith();
			expect(deleteChallengeByValue).toHaveBeenCalledWith(mockKnownUserChallenge.challenge);
		});
	});

	describe('credential marshalling', () => {
		it('passes the public key as bytes, not the stored base64 string', async () => {
			await callWith();
			const { credential } = vi.mocked(verifyAuthenticationResponse).mock.calls[0][0];
			expect(credential.publicKey).toBeInstanceOf(Uint8Array);
			expect(Array.from(credential.publicKey)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
		});

		it('parses transports from the stored JSON string', async () => {
			await callWith();
			const { credential } = vi.mocked(verifyAuthenticationResponse).mock.calls[0][0];
			expect(credential.transports).toEqual(['internal', 'hybrid']);
		});

		it('passes undefined transports when the column is null', async () => {
			vi.mocked(getPasskeyByCredentialId).mockResolvedValue({
				...mockStoredCredential,
				transports: null
			} as never);
			await callWith();
			const { credential } = vi.mocked(verifyAuthenticationResponse).mock.calls[0][0];
			expect(credential.transports).toBeUndefined();
		});

		it('passes undefined transports when the column is malformed rather than failing', async () => {
			vi.mocked(getPasskeyByCredentialId).mockResolvedValue({
				...mockStoredCredential,
				transports: 'not json'
			} as never);
			await expect(callWith()).resolves.toMatchObject({ userId: 'user-123' });
			const { credential } = vi.mocked(verifyAuthenticationResponse).mock.calls[0][0];
			expect(credential.transports).toBeUndefined();
		});

		it('passes the stored counter as the expected starting point', async () => {
			await callWith();
			const { credential } = vi.mocked(verifyAuthenticationResponse).mock.calls[0][0];
			expect(credential.counter).toBe(5);
		});
	});

	describe('discoverable-credential flow', () => {
		beforeEach(() => {
			vi.mocked(getChallengeByValue).mockResolvedValue(mockDiscoverableChallenge as never);
		});

		it('succeeds without a userId on the challenge', async () => {
			await expect(callWith()).resolves.toMatchObject({ userId: 'user-123' });
		});

		it('does not reject when the credential belongs to any user', async () => {
			vi.mocked(getPasskeyByCredentialId).mockResolvedValue({
				...mockStoredCredential,
				userId: 'someone-else'
			} as never);
			await expect(callWith()).resolves.toMatchObject({ userId: 'someone-else' });
		});
	});

	describe('rejection paths', () => {
		it('rejects with CHALLENGE_NOT_FOUND when the challenge is missing or expired', async () => {
			vi.mocked(getChallengeByValue).mockResolvedValue(null as never);
			await expect(callWith()).rejects.toMatchObject({
				code: PasskeyErrorCode.CHALLENGE_NOT_FOUND
			});
			expect(verifyAuthenticationResponse).not.toHaveBeenCalled();
		});

		it('rejects with CREDENTIAL_NOT_FOUND for an unknown credential id', async () => {
			vi.mocked(getPasskeyByCredentialId).mockResolvedValue(null as never);
			await expect(callWith()).rejects.toMatchObject({
				code: PasskeyErrorCode.CREDENTIAL_NOT_FOUND
			});
			expect(verifyAuthenticationResponse).not.toHaveBeenCalled();
		});

		it('rejects with CHALLENGE_USER_MISMATCH when the credential belongs to another user', async () => {
			vi.mocked(getPasskeyByCredentialId).mockResolvedValue({
				...mockStoredCredential,
				userId: 'someone-else'
			} as never);
			await expect(callWith()).rejects.toMatchObject({
				code: PasskeyErrorCode.CHALLENGE_USER_MISMATCH
			});
			expect(verifyAuthenticationResponse).not.toHaveBeenCalled();
		});

		it('wraps a throwing verifier in ASSERTION_INVALID and preserves the cause', async () => {
			vi.mocked(verifyAuthenticationResponse).mockRejectedValue(
				new Error('signature mismatch') as never
			);
			const err = await callWith().catch((e) => e);
			expect(err).toBeInstanceOf(PasskeyError);
			expect(err.code).toBe(PasskeyErrorCode.ASSERTION_INVALID);
			expect(err.cause?.message).toBe('signature mismatch');
		});

		it('rejects with VERIFICATION_FAILED when verified is false', async () => {
			vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
				verified: false,
				authenticationInfo: undefined
			} as never);
			await expect(callWith()).rejects.toMatchObject({
				code: PasskeyErrorCode.VERIFICATION_FAILED
			});
		});

		it('does not update the counter or delete the challenge when verification fails', async () => {
			vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
				verified: false,
				authenticationInfo: undefined
			} as never);
			await callWith().catch(() => {});
			expect(updatePasskeyCounter).not.toHaveBeenCalled();
			expect(deleteChallengeByValue).not.toHaveBeenCalled();
		});

		it('rejects with STORAGE_FAILED when the counter cannot be persisted', async () => {
			vi.mocked(updatePasskeyCounter).mockRejectedValue(new Error('db down') as never);
			await expect(callWith()).rejects.toMatchObject({
				code: PasskeyErrorCode.STORAGE_FAILED
			});
		});
	});

	it('swallows a challenge-deletion failure, since the credential is already verified', async () => {
		vi.mocked(deleteChallengeByValue).mockRejectedValue(new Error('db down') as never);
		await expect(callWith()).resolves.toMatchObject({ newCounter: 6 });
	});
});
