export const PasskeyErrorCode = {
	CHALLENGE_NOT_FOUND: 'CHALLENGE_NOT_FOUND',
	CHALLENGE_EXPIRED: 'CHALLENGE_EXPIRED',
	CHALLENGE_USER_MISMATCH: 'CHALLENGE_USER_MISMATCH',
	ATTESTATION_INVALID: 'ATTESTATION_INVALID',
	VERIFICATION_FAILED: 'VERIFICATION_FAILED',
	STORAGE_FAILED: 'STORAGE_FAILED'
} as const;

export type PasskeyErrorCode = (typeof PasskeyErrorCode)[keyof typeof PasskeyErrorCode];

export class PasskeyError extends Error {
	constructor(
		message: string,
		public readonly code: PasskeyErrorCode,
		public readonly cause?: Error
	) {
		super(message);
		this.name = 'PasskeyError';
	}
}
