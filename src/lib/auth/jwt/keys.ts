import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose';
import type { JWK, KeyLike } from 'jose';
import { InvalidSigningKeyError } from '../errors';

const ALG = 'EdDSA';
const CRV = 'Ed25519';

export interface SigningKeyPair {
	privateKey: KeyLike;
	publicKey: KeyLike;
	kid: string;
}

/** Private key JWK with required fields for storage */
export interface PrivateKeyJwk extends JWK {
	kty: 'OKP';
	crv: 'Ed25519';
	d: string;
	x: string;
	kid?: string;
	use?: string;
	alg?: string;
}

/** Public key JWK for JWKS endpoint */
export interface SigningKeyJwk extends JWK {
	kty: 'OKP';
	crv: 'Ed25519';
	x: string;
	kid: string;
	use: string;
	alg: string;
}

/**
 * Generate a new EdDSA Ed25519 signing key pair.
 * Returns the key pair with a computed kid (SHA-256 thumbprint of public JWK).
 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
	const { privateKey, publicKey } = await generateKeyPair(ALG, { crv: CRV, extractable: true });
	const publicJwk = await exportJWK(publicKey);
	const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
	return { privateKey, publicKey, kid };
}

/**
 * Compute the key ID (kid) as SHA-256 thumbprint of the public key JWK.
 */
export async function computeKeyId(publicKey: KeyLike): Promise<string> {
	const jwk = await exportJWK(publicKey);
	return calculateJwkThumbprint(jwk, 'sha256');
}

/**
 * Load a signing key from the IDENTIKEY_SIGNING_KEY environment variable.
 * Expects a JSON Web Key (JWK) format. Validates the key is EdDSA Ed25519.
 * Throws InvalidSigningKeyError on failure.
 */
export async function loadSigningKey(): Promise<SigningKeyPair> {
	const jwkJson = process.env.IDENTIKEY_SIGNING_KEY;
	if (!jwkJson) {
		throw new InvalidSigningKeyError('IDENTIKEY_SIGNING_KEY environment variable is not set');
	}

	let jwk: PrivateKeyJwk;
	try {
		jwk = JSON.parse(jwkJson) as PrivateKeyJwk;
	} catch (err) {
		throw new InvalidSigningKeyError(
			'Failed to parse IDENTIKEY_SIGNING_KEY: must be valid JSON (JWK format)',
			err instanceof Error ? err : undefined
		);
	}

	// Validate required JWK fields
	if (jwk.kty !== 'OKP' || jwk.crv !== CRV) {
		throw new InvalidSigningKeyError(
			`Invalid key curve: expected OKP ${CRV}, got ${jwk.kty} ${jwk.crv ?? 'unknown'}`
		);
	}
	if (!jwk.d || !jwk.x) {
		throw new InvalidSigningKeyError(
			'Invalid JWK: missing required fields "d" (private key) or "x" (public key)'
		);
	}

	let privateKey: KeyLike;
	try {
		privateKey = (await importJWK(jwk, ALG)) as KeyLike;
	} catch (err) {
		throw new InvalidSigningKeyError(
			'Failed to import IDENTIKEY_SIGNING_KEY: invalid Ed25519 JWK',
			err instanceof Error ? err : undefined
		);
	}

	// Derive public key by importing without the private component
	const { d: _, ...publicJwkFields } = jwk;
	const publicJwk = publicJwkFields as JWK;
	const kid = jwk.kid ?? (await calculateJwkThumbprint(publicJwk, 'sha256'));
	const publicKey = (await importJWK(publicJwk, ALG)) as KeyLike;

	return { privateKey, publicKey, kid };
}

/**
 * Export the public key as a JWK with all required JWKS fields.
 */
export async function getPublicKeyJwk(keyPair: SigningKeyPair): Promise<SigningKeyJwk> {
	const jwk = await exportJWK(keyPair.publicKey);
	return {
		...jwk,
		kid: keyPair.kid,
		use: 'sig',
		alg: ALG
	} as SigningKeyJwk;
}

/**
 * Export the private key as a JWK (for storage in IDENTIKEY_SIGNING_KEY).
 * Includes kid, use, and alg fields for self-documenting storage.
 */
export async function exportPrivateKeyJwk(keyPair: SigningKeyPair): Promise<PrivateKeyJwk> {
	const jwk = await exportJWK(keyPair.privateKey);
	return {
		...jwk,
		kid: keyPair.kid,
		use: 'sig',
		alg: ALG
	} as PrivateKeyJwk;
}
