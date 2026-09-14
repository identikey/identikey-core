import { describe, expect, it } from 'vitest';

import { ErrorCodes, IdentiKeyError, type ErrorCode } from './errors';

describe('ErrorCodes', () => {
	it('contains the expected stable set of codes', () => {
		const codes: ErrorCode[] = [
			ErrorCodes.USER_NOT_FOUND,
			ErrorCodes.APP_NOT_FOUND,
			ErrorCodes.GUILD_NOT_FOUND,
			ErrorCodes.AUTH_FLOW_NOT_FOUND,
			ErrorCodes.EXECUTION_NOT_FOUND,
			ErrorCodes.FLOW_IS_BUILTIN,
			ErrorCodes.INVALID_PROVIDER,
			ErrorCodes.UNAUTHORIZED,
			ErrorCodes.CONNECTION_FAILED,
			ErrorCodes.INVALID_INPUT
		];

		expect(new Set(Object.values(ErrorCodes))).toEqual(new Set(codes));
	});
});

describe('IdentiKeyError', () => {
	it('preserves message, code, and cause', () => {
		const cause = new Error('root cause');
		const err = new IdentiKeyError('wrapped', ErrorCodes.CONNECTION_FAILED, cause);

		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe('IdentiKeyError');
		expect(err.message).toBe('wrapped');
		expect(err.code).toBe(ErrorCodes.CONNECTION_FAILED);
		expect(err.cause).toBe(cause);
		expect(err.stack).toBeDefined();
	});
});


