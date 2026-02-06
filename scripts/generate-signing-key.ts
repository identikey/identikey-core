#!/usr/bin/env bun
/**
 * Generate an EdDSA Ed25519 signing key for IDENTIKEY_SIGNING_KEY env var.
 * Outputs a self-documenting JWK with kid, use, and alg fields.
 *
 * Usage: bun run generate-key
 */
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';

const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const publicJwk = await exportJWK(publicKey);
const privateJwk = await exportJWK(privateKey);
const kid = await calculateJwkThumbprint(publicJwk, 'sha256');

// Build self-documenting JWK with metadata
const fullJwk = {
	...privateJwk,
	kid,
	use: 'sig',
	alg: 'EdDSA'
};

const jwkJson = JSON.stringify(fullJwk);

console.log('# Ed25519 signing key for IdentiKey (JWK format)');
console.log(`# kid: ${kid}`);
console.log(`# Generated: ${new Date().toISOString()}`);
console.log('#');
console.log('# Add to your .env file (single line):');
console.log(`IDENTIKEY_SIGNING_KEY='${jwkJson}'`);
console.log('#');
console.log('# Or for readability:');
console.log(JSON.stringify(fullJwk, null, 2));
