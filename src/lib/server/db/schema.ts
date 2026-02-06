import { pgTable, serial, integer, text, timestamp, uuid, index } from 'drizzle-orm/pg-core';

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

export type Session = typeof session.$inferSelect;

export type User = typeof user.$inferSelect;

export type Challenge = typeof challenges.$inferSelect;
