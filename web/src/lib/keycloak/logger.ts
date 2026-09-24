import pino from 'pino';

// No worker transport. Bun defaults NODE_ENV to "development", and pino-pretty
// is not a dependency — a `target: "pino-pretty"` logger crashes `bun run build`
// inside the Mjolnir build VM.
export const logger = pino({
	level: process.env.LOG_LEVEL ?? 'info'
});


