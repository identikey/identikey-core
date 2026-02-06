import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema';
import type { Db } from './index';

let dbInstance: Db | null = null;

function getDb(): Db {
	if (dbInstance) return dbInstance;
	const url = process.env.DATABASE_URL_TEST;
	if (!url) throw new Error('DATABASE_URL_TEST is not set');
	if (!/test/i.test(url))
		throw new Error('DATABASE_URL_TEST must reference a test database (url should contain "test")');
	const client = postgres(url, { max: 5, connect_timeout: 5, idle_timeout: 10 });
	dbInstance = drizzle(client, { schema });
	return dbInstance;
}

/**
 * Wraps a test callback in a transaction that always rolls back.
 * Uses drizzle transaction with explicit rollback for test isolation.
 */
export async function withTestDb<T>(fn: (db: Db) => Promise<T>): Promise<T> {
	const db = getDb();
	// Use a rollback-only transaction by throwing after callback completes
	const rollbackError = Symbol('rollback');
	let result: T;
	try {
		await db.transaction(async (tx) => {
			result = await fn(tx as unknown as Db);
			// Force rollback by throwing
			throw rollbackError;
		});
	} catch (e) {
		if (e !== rollbackError) throw e;
	}
	return result!;
}
