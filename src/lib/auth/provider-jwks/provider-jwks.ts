import { createRemoteJWKSet } from 'jose';
import type { FlattenedJWSInput, JWSHeaderParameters, GetKeyFunction } from 'jose';
import { ProviderJwksError } from '../errors';

export const APPLE_JWKS_URI = 'https://appleid.apple.com/auth/keys';
export const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';

export type JwkSetKeyFunction = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

/**
 * Provider registry: maps provider ID to JWKS URI.
 *
 * Adding a new OIDC provider:
 *  1. Add its JWKS URI as a constant (e.g. `export const EXAMPLE_JWKS_URI = '...'`)
 *  2. Add the entry to PROVIDER_JWKS_URIS below (e.g. `example: EXAMPLE_JWKS_URI`)
 *  3. Export a convenience getter (e.g. `export function getExampleJwkSet() { return getProviderJwkSet('example'); }`)
 *  4. Re-export from index.ts
 */
const PROVIDER_JWKS_URIS: Record<string, string> = {
	apple: APPLE_JWKS_URI,
	google: GOOGLE_JWKS_URI,
};

// Cached key functions per provider — createRemoteJWKSet handles HTTP caching internally
const jwkSetCache = new Map<string, JwkSetKeyFunction>();

/**
 * Get the JWKS key-resolution function for a registered provider.
 * The returned function is suitable for use with `jose.jwtVerify(token, keyFn, options)`.
 * createRemoteJWKSet handles caching, key selection by kid/alg, and refresh on miss.
 *
 * @throws {ProviderJwksError} if the provider ID is not registered
 */
export function getProviderJwkSet(providerId: string): JwkSetKeyFunction {
	const uri = PROVIDER_JWKS_URIS[providerId];
	if (!uri) {
		throw new ProviderJwksError(`Unknown provider: ${providerId}`);
	}

	let cached = jwkSetCache.get(providerId);
	if (!cached) {
		const remoteKeyFn = createRemoteJWKSet(new URL(uri));
		// Wrap to convert fetch/parse errors into ProviderJwksError
		cached = (async (...args: Parameters<JwkSetKeyFunction>) => {
			try {
				return await remoteKeyFn(...args);
			} catch (err) {
				if (err instanceof ProviderJwksError) throw err;
				throw new ProviderJwksError(
					`Failed to resolve JWKS for provider: ${providerId}`,
					err instanceof Error ? err : undefined,
				);
			}
		}) as JwkSetKeyFunction;
		jwkSetCache.set(providerId, cached);
	}
	return cached;
}

/** @internal Reset cached key functions (for testing only). */
export function _resetProviderCache(): void {
	jwkSetCache.clear();
}

/** Get Apple JWKS key-resolution function. */
export function getAppleJwkSet(): JwkSetKeyFunction {
	return getProviderJwkSet('apple');
}

/** Get Google JWKS key-resolution function. */
export function getGoogleJwkSet(): JwkSetKeyFunction {
	return getProviderJwkSet('google');
}
