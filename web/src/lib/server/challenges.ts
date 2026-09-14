import { eq, and, gt } from 'drizzle-orm';
import { db as appDb, type Db } from '$lib/server/db';
import { challenges } from '$lib/server/db/schema';
import type { Challenge } from '$lib/server/db/schema';

const TTL_MS = 5 * 60 * 1000;

export type ChallengeType = 'registration' | 'authentication';

export type CreateChallengeParams = {
	userId: string | null;
	challenge: string;
	type: ChallengeType;
};

export function createChallenge(params: CreateChallengeParams, db: Db = appDb): Promise<Challenge> {
	const expiresAt = new Date(Date.now() + TTL_MS);
	return db
		.insert(challenges)
		.values({
			userId: params.userId,
			challenge: params.challenge,
			type: params.type,
			expiresAt
		})
		.returning()
		.then((rows) => rows[0]!);
}

export async function getChallengeByValue(challenge: string, db: Db = appDb): Promise<Challenge | null> {
	const now = new Date();
	const rows = await db
		.select()
		.from(challenges)
		.where(and(eq(challenges.challenge, challenge), gt(challenges.expiresAt, now)))
		.limit(1);
	const row = rows[0] ?? null;
	if (!row) {
		const expired = await db
			.select()
			.from(challenges)
			.where(eq(challenges.challenge, challenge))
			.limit(1);
		if (expired[0]) {
			await db.delete(challenges).where(eq(challenges.id, expired[0].id));
		}
		return null;
	}
	return row;
}

export function deleteChallenge(id: string, db: Db = appDb): Promise<unknown> {
	return db.delete(challenges).where(eq(challenges.id, id));
}

export async function deleteChallengeByValue(challenge: string, db: Db = appDb): Promise<unknown> {
	const rows = await db
		.select({ id: challenges.id })
		.from(challenges)
		.where(eq(challenges.challenge, challenge))
		.limit(1);
	if (rows[0]) {
		return db.delete(challenges).where(eq(challenges.id, rows[0].id));
	}
	return Promise.resolve();
}
