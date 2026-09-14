import 'dotenv/config';
import { describe, it, expect, beforeEach } from 'vitest';
import { withTestDb } from '$lib/server/db/test-utils';
import { getChallengeByValue } from '$lib/server/challenges';
import { generateRegistrationChallenge } from './registration-options';

/**
 * Integration test: verifies the actual @simplewebauthn/server challenge
 * round-trips through our DB correctly (format compatibility).
 */
describe('registration challenge DB round-trip', () => {
	beforeEach(() => {
		process.env.WEBAUTHN_RP_ID = 'localhost';
		process.env.WEBAUTHN_RP_NAME = 'IdentiKey';
	});

	it('generates options via @simplewebauthn/server and retrieves the challenge from DB', async () => {
		await withTestDb(async (db) => {
			const options = await generateRegistrationChallenge(
				{ userId: 'user-integration-1', userName: 'testuser@example.com' },
				db
			);

			expect(options.challenge).toBeDefined();
			expect(typeof options.challenge).toBe('string');
			expect(options.challenge.length).toBeGreaterThan(0);
			expect(options.rp.id).toBe('localhost');
			expect(options.user.name).toBe('testuser@example.com');

			const found = await getChallengeByValue(options.challenge, db);
			expect(found).not.toBeNull();
			expect(found!.userId).toBe('user-integration-1');
			expect(found!.challenge).toBe(options.challenge);
			expect(found!.type).toBe('registration');
		});
	});
});
