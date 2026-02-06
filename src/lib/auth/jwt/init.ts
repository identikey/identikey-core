import { logger } from '../../keycloak/logger';
import { loadSigningKey } from './keys';
import { InvalidSigningKeyError } from '../errors';
import type { SigningKeyPair } from './keys';

let signingKey: SigningKeyPair | null = null;

/**
 * Initialize the signing key on service startup.
 * Loads and validates the key from IDENTIKEY_SIGNING_KEY env var.
 * Exits the process on failure.
 */
export async function initializeSigningKey(): Promise<SigningKeyPair> {
	try {
		signingKey = await loadSigningKey();
		logger.info({ kid: signingKey.kid }, 'Signing key loaded successfully');
		return signingKey;
	} catch (err) {
		if (err instanceof InvalidSigningKeyError) {
			logger.error({ error: err.message }, 'Failed to load signing key');
		} else {
			logger.error('Unexpected error loading signing key');
		}
		process.exit(1);
	}
}

/**
 * Get the current signing key. Throws if not initialized.
 */
export function getSigningKey(): SigningKeyPair {
	if (!signingKey) {
		throw new Error('Signing key not initialized. Call initializeSigningKey() first.');
	}
	return signingKey;
}
