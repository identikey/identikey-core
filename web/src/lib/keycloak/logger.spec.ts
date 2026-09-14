import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('logger', () => {
	const ORIGINAL_ENV = { ...process.env };

	beforeEach(() => {
		process.env = { ...ORIGINAL_ENV };
		vi.resetModules();
	});

	it('initializes with default info level when LOG_LEVEL is unset', async () => {
		delete process.env.LOG_LEVEL;

		const { logger } = await import('./logger');

		expect(logger.level).toBe('info');
	});

	it('honors LOG_LEVEL from environment', async () => {
		process.env.LOG_LEVEL = 'debug';

		const { logger } = await import('./logger');

		expect(logger.level).toBe('debug');
	});
});

