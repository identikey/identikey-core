import 'dotenv/config';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withTestDb } from './db/test-utils';
import {
	createChallenge,
	getChallengeByValue,
	deleteChallenge,
	deleteChallengeByValue,
	type ChallengeType
} from './challenges';

describe('challenge service', () => {
	describe('createChallenge', () => {
		it('creates a challenge and returns the row with id', async () => {
			await withTestDb(async (db) => {
				const result = await createChallenge(
					{ userId: 'user-123', challenge: 'test-challenge-1', type: 'registration' },
					db
				);

				expect(result.id).toBeDefined();
				expect(result.userId).toBe('user-123');
				expect(result.challenge).toBe('test-challenge-1');
				expect(result.type).toBe('registration');
				expect(result.expiresAt).toBeInstanceOf(Date);
				expect(result.createdAt).toBeInstanceOf(Date);
			});
		});

		it('sets expiresAt to approximately 5 minutes from now', async () => {
			await withTestDb(async (db) => {
				const before = Date.now();
				const result = await createChallenge(
					{ userId: null, challenge: 'test-challenge-2', type: 'authentication' },
					db
				);
				const after = Date.now();

				const expectedMinMs = before + 5 * 60 * 1000;
				const expectedMaxMs = after + 5 * 60 * 1000;
				const expiresAtMs = result.expiresAt.getTime();

				expect(expiresAtMs).toBeGreaterThanOrEqual(expectedMinMs - 100);
				expect(expiresAtMs).toBeLessThanOrEqual(expectedMaxMs + 100);
			});
		});

		it('allows null userId for discoverable credential auth', async () => {
			await withTestDb(async (db) => {
				const result = await createChallenge(
					{ userId: null, challenge: 'test-challenge-3', type: 'authentication' },
					db
				);

				expect(result.userId).toBeNull();
			});
		});

		it('enforces unique challenge constraint', async () => {
			await withTestDb(async (db) => {
				await createChallenge(
					{ userId: 'user-1', challenge: 'duplicate-challenge', type: 'registration' },
					db
				);

				await expect(
					createChallenge(
						{ userId: 'user-2', challenge: 'duplicate-challenge', type: 'authentication' },
						db
					)
				).rejects.toThrow();
			});
		});
	});

	describe('getChallengeByValue', () => {
		it('returns the challenge row when found and not expired', async () => {
			await withTestDb(async (db) => {
				const created = await createChallenge(
					{ userId: 'user-456', challenge: 'find-me-challenge', type: 'registration' },
					db
				);

				const result = await getChallengeByValue('find-me-challenge', db);

				expect(result).not.toBeNull();
				expect(result!.id).toBe(created.id);
				expect(result!.userId).toBe('user-456');
				expect(result!.challenge).toBe('find-me-challenge');
				expect(result!.type).toBe('registration');
			});
		});

		it('returns null for unknown challenge', async () => {
			await withTestDb(async (db) => {
				const result = await getChallengeByValue('non-existent-challenge', db);

				expect(result).toBeNull();
			});
		});

		it('returns null for expired challenge and cleans up', async () => {
			await withTestDb(async (db) => {
				// Insert an expired challenge directly using raw insert
				const { challenges } = await import('./db/schema');
				const expiredDate = new Date(Date.now() - 60 * 1000); // 1 minute ago
				await db.insert(challenges).values({
					userId: 'user-expired',
					challenge: 'expired-challenge',
					type: 'registration',
					expiresAt: expiredDate
				});

				const result = await getChallengeByValue('expired-challenge', db);

				expect(result).toBeNull();

				// Verify cleanup happened (on-read cleanup)
				const { eq } = await import('drizzle-orm');
				const remaining = await db
					.select()
					.from(challenges)
					.where(eq(challenges.challenge, 'expired-challenge'));
				expect(remaining.length).toBe(0);
			});
		});
	});

	describe('deleteChallenge', () => {
		it('deletes challenge by id', async () => {
			await withTestDb(async (db) => {
				const created = await createChallenge(
					{ userId: 'user-del', challenge: 'delete-by-id', type: 'registration' },
					db
				);

				await deleteChallenge(created.id, db);

				const result = await getChallengeByValue('delete-by-id', db);
				expect(result).toBeNull();
			});
		});
	});

	describe('deleteChallengeByValue', () => {
		it('deletes challenge by value', async () => {
			await withTestDb(async (db) => {
				await createChallenge(
					{ userId: 'user-del2', challenge: 'delete-by-value', type: 'authentication' },
					db
				);

				await deleteChallengeByValue('delete-by-value', db);

				const result = await getChallengeByValue('delete-by-value', db);
				expect(result).toBeNull();
			});
		});

		it('handles non-existent challenge gracefully', async () => {
			await withTestDb(async (db) => {
				// Should not throw
				await expect(deleteChallengeByValue('does-not-exist', db)).resolves.not.toThrow();
			});
		});
	});
});
