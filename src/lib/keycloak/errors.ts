export const ErrorCodes = {
	USER_NOT_FOUND: 'USER_NOT_FOUND',
	APP_NOT_FOUND: 'APP_NOT_FOUND',
	GUILD_NOT_FOUND: 'GUILD_NOT_FOUND',
	AUTH_FLOW_NOT_FOUND: 'AUTH_FLOW_NOT_FOUND',
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
