import { eq } from 'drizzle-orm';
import { db as appDb, type Db } from '$lib/server/db';
import { passkeyCredentials } from '$lib/server/db/schema';
import type { PasskeyCredential } from '$lib/server/db/schema';

export type StorePasskeyParams = {
	userId: string;
	credentialId: string;
	publicKey: string;
	counter: number;
	transports?: string[];
	deviceType: string;
	backedUp: boolean;
};

export async function storePasskeyCredential(
	params: StorePasskeyParams,
	db: Db = appDb
): Promise<PasskeyCredential> {
	const rows = await db
		.insert(passkeyCredentials)
		.values({
			userId: params.userId,
			credentialId: params.credentialId,
			publicKey: params.publicKey,
			counter: params.counter,
			transports: params.transports ? JSON.stringify(params.transports) : null,
			deviceType: params.deviceType,
			backedUp: params.backedUp
		})
		.returning();
	return rows[0]!;
}

export async function getPasskeyByCredentialId(
	credentialId: string,
	db: Db = appDb
): Promise<PasskeyCredential | null> {
	const rows = await db
		.select()
		.from(passkeyCredentials)
		.where(eq(passkeyCredentials.credentialId, credentialId))
		.limit(1);
	return rows[0] ?? null;
}

export async function getPasskeysByUserId(
	userId: string,
	db: Db = appDb
): Promise<PasskeyCredential[]> {
	return db
		.select()
		.from(passkeyCredentials)
		.where(eq(passkeyCredentials.userId, userId));
}

export async function updatePasskeyCounter(
	credentialId: string,
	counter: number,
	db: Db = appDb
): Promise<void> {
	await db
		.update(passkeyCredentials)
		.set({ counter, lastUsedAt: new Date() })
		.where(eq(passkeyCredentials.credentialId, credentialId));
}

export async function deletePasskeyCredential(
	credentialId: string,
	db: Db = appDb
): Promise<void> {
	await db
		.delete(passkeyCredentials)
		.where(eq(passkeyCredentials.credentialId, credentialId));
}
