import { pgTable, serial, integer, text, timestamp, uuid, index, boolean } from 'drizzle-orm/pg-core';

export const user = pgTable('user', {
	id: text('id').primaryKey(),
	age: integer('age')
});

export const session = pgTable('session', {
	id: text('id').primaryKey(),
	userId: text('user_id')
		.notNull()
		.references(() => user.id),
	expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull()
});

export const challenges = pgTable(
	'challenges',
	{
		id: uuid('id').primaryKey().defaultRandom(),
		userId: text('user_id'),
		challenge: text('challenge').notNull().unique(),
		type: text('type').notNull(),
		expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
		createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow()
	},
	(t) => [index('idx_challenges_expires_at').on(t.expiresAt)]
);

export const passkeyCredentials = pgTable(
	'passkey_credentials',
	{
		id: uuid('id').primaryKey().defaultRandom(),
		userId: text('user_id').notNull(),
		credentialId: text('credential_id').notNull().unique(),
		publicKey: text('public_key').notNull(),
		counter: integer('counter').notNull().default(0),
		transports: text('transports'),
		deviceType: text('device_type').notNull(),
		backedUp: boolean('backed_up').notNull().default(false),
		createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
		lastUsedAt: timestamp('last_used_at', { withTimezone: true, mode: 'date' })
	},
	(t) => [index('idx_passkey_credentials_user_id').on(t.userId)]
);

export type Session = typeof session.$inferSelect;

export type User = typeof user.$inferSelect;

export type Challenge = typeof challenges.$inferSelect;

export type PasskeyCredential = typeof passkeyCredentials.$inferSelect;
