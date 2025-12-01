export const ErrorCodes = {
	USER_NOT_FOUND: 'USER_NOT_FOUND',
	APP_NOT_FOUND: 'APP_NOT_FOUND',
	GUILD_NOT_FOUND: 'GUILD_NOT_FOUND',
	AUTH_FLOW_NOT_FOUND: 'AUTH_FLOW_NOT_FOUND',
	EXECUTION_NOT_FOUND: 'EXECUTION_NOT_FOUND',
	FLOW_IS_BUILTIN: 'FLOW_IS_BUILTIN',
	INVALID_PROVIDER: 'INVALID_PROVIDER',
	UNAUTHORIZED: 'UNAUTHORIZED',
	CONNECTION_FAILED: 'CONNECTION_FAILED',
	INVALID_INPUT: 'INVALID_INPUT'
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

export class IdentiKeyError extends Error {
	constructor(
		message: string,
		public code: ErrorCode,
		public cause?: Error
	) {
		super(message);
		this.name = 'IdentiKeyError';
	}
}
