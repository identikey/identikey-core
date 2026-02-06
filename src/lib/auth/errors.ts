export class InvalidSigningKeyError extends Error {
	constructor(
		message: string,
		public readonly cause?: Error
	) {
		super(message);
		this.name = 'InvalidSigningKeyError';
	}
}

export const VerificationFailureCode = {
	EXPIRED: 'EXPIRED',
	INVALID_SIGNATURE: 'INVALID_SIGNATURE',
	INVALID_ISSUER: 'INVALID_ISSUER',
	INVALID_AUDIENCE: 'INVALID_AUDIENCE',
	MALFORMED: 'MALFORMED',
} as const;

export type VerificationFailureCode = (typeof VerificationFailureCode)[keyof typeof VerificationFailureCode];

export class TokenVerificationError extends Error {
	constructor(
		message: string,
		public readonly code: VerificationFailureCode,
		public readonly cause?: Error,
	) {
		super(message);
		this.name = 'TokenVerificationError';
	}

	static fromJoseError(err: unknown): TokenVerificationError {
		if (!(err instanceof Error)) {
			return new TokenVerificationError('Token verification failed', VerificationFailureCode.MALFORMED);
		}

		const name = err.constructor?.name;
		const claim = (err as unknown as Record<string, unknown>).claim as string | undefined;

		if (name === 'JWTExpired') {
			return new TokenVerificationError('Token has expired', VerificationFailureCode.EXPIRED, err);
		}
		if (name === 'JWSSignatureVerificationFailed' || err.message.includes('signature verification failed')) {
			return new TokenVerificationError('Invalid token signature', VerificationFailureCode.INVALID_SIGNATURE, err);
		}
		if (name === 'JWTClaimValidationFailed' && claim) {
			if (claim === 'iss') {
				return new TokenVerificationError('Invalid token issuer', VerificationFailureCode.INVALID_ISSUER, err);
			}
			if (claim === 'aud') {
				return new TokenVerificationError('Invalid token audience', VerificationFailureCode.INVALID_AUDIENCE, err);
			}
			if (claim === 'exp') {
				return new TokenVerificationError('Token has expired', VerificationFailureCode.EXPIRED, err);
			}
		}

		return new TokenVerificationError('Malformed or invalid token', VerificationFailureCode.MALFORMED, err);
	}
}
