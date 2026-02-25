import 'dotenv/config';
import { describe, it, expect } from 'vitest';
import { withTestDb } from '$lib/server/db/test-utils';
import {
	storePasskeyCredential,
	getPasskeyByCredentialId,
	getPasskeysByUserId,
	updatePasskeyCounter,
	deletePasskeyCredential
} from './credential-store';

describe('credential store', () => {
	const baseParams = {
		userId: 'user-abc',
		credentialId: 'cred-id-123',
		publicKey: 'AQIDBA==',
		counter: 0,
		transports: ['internal', 'hybrid'],
		deviceType: 'multiDevice',
		backedUp: true
	};

	describe('storePasskeyCredential', () => {
		it('stores and returns the credential', async () => {
			await withTestDb(async (db) => {
				const result = await storePasskeyCredential(baseParams, db);

				expect(result.id).toBeDefined();
				expect(result.userId).toBe('user-abc');
				expect(result.credentialId).toBe('cred-id-123');
				expect(result.publicKey).toBe('AQIDBA==');
				expect(result.counter).toBe(0);
				expect(result.transports).toBe(JSON.stringify(['internal', 'hybrid']));
				expect(result.deviceType).toBe('multiDevice');
				expect(result.backedUp).toBe(true);
				expect(result.createdAt).toBeInstanceOf(Date);
				expect(result.lastUsedAt).toBeNull();
			});
		});

		it('enforces unique credentialId', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				await expect(storePasskeyCredential(baseParams, db)).rejects.toThrow();
			});
		});

		it('supports multiple passkeys per user', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				await storePasskeyCredential(
					{ ...baseParams, credentialId: 'cred-id-456' },
					db
				);

				const passkeys = await getPasskeysByUserId('user-abc', db);
				expect(passkeys).toHaveLength(2);
			});
		});

		it('stores null transports when none provided', async () => {
			await withTestDb(async (db) => {
				const result = await storePasskeyCredential(
					{ ...baseParams, credentialId: 'cred-no-transport', transports: undefined },
					db
				);
				expect(result.transports).toBeNull();
			});
		});
	});

	describe('getPasskeyByCredentialId', () => {
		it('returns the credential when found', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				const result = await getPasskeyByCredentialId('cred-id-123', db);

				expect(result).not.toBeNull();
				expect(result!.credentialId).toBe('cred-id-123');
				expect(result!.userId).toBe('user-abc');
			});
		});

		it('returns null for unknown credentialId', async () => {
			await withTestDb(async (db) => {
				const result = await getPasskeyByCredentialId('nonexistent', db);
				expect(result).toBeNull();
			});
		});
	});

	describe('getPasskeysByUserId', () => {
		it('returns all passkeys for a user', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				await storePasskeyCredential(
					{ ...baseParams, credentialId: 'cred-second' },
					db
				);

				const results = await getPasskeysByUserId('user-abc', db);
				expect(results).toHaveLength(2);
			});
		});

		it('returns empty array for user with no passkeys', async () => {
			await withTestDb(async (db) => {
				const results = await getPasskeysByUserId('nobody', db);
				expect(results).toHaveLength(0);
			});
		});
	});

	describe('updatePasskeyCounter', () => {
		it('updates counter and lastUsedAt', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				await updatePasskeyCounter('cred-id-123', 5, db);

				const updated = await getPasskeyByCredentialId('cred-id-123', db);
				expect(updated!.counter).toBe(5);
				expect(updated!.lastUsedAt).toBeInstanceOf(Date);
			});
		});
	});

	describe('deletePasskeyCredential', () => {
		it('deletes the credential', async () => {
			await withTestDb(async (db) => {
				await storePasskeyCredential(baseParams, db);
				await deletePasskeyCredential('cred-id-123', db);

				const result = await getPasskeyByCredentialId('cred-id-123', db);
				expect(result).toBeNull();
			});
		});

		it('does not throw for non-existent credential', async () => {
			await withTestDb(async (db) => {
				await expect(
					deletePasskeyCredential('does-not-exist', db)
				).resolves.not.toThrow();
			});
		});
	});
});
