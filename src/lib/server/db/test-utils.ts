import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema';
import type { Db } from './index';

let pool: ReturnType<typeof postgres> | null = null;

function getPool() {
	if (pool) return pool;
	const url = process.env.DATABASE_URL_TEST;
	if (!url) throw new Error('DATABASE_URL_TEST is not set');
	if (!/test/i.test(url))
		throw new Error('DATABASE_URL_TEST must reference a test database (url should contain "test")');
	pool = postgres(url, { max: 5, connect_timeout: 5, idle_timeout: 10 });
	return pool;
}

/**
 * Wraps a test callback in a transaction that always rolls back.
 * Each call reserves its own connection, so concurrent tests are safe.
 */
export async function withTestDb<T>(fn: (db: Db) => Promise<T>): Promise<T> {
	const p = getPool();
	const conn = await p.reserve();
	await conn`BEGIN`;
	try {
		return await fn(drizzle(conn, { schema }) as unknown as Db);
	} finally {
		await conn`ROLLBACK`;
		conn.release();
	}
}
