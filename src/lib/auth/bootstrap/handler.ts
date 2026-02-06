/**
 * Bootstrap handler abstraction: verify identity token and provision user in one call.
 * Epic 10 provision endpoints (POST /apple-provision, POST /google-provision) use
 * getBootstrapHandler(provider).verifyAndProvision(token). Future providers (e.g. email, SMS in Epic 13)
 * implement the same interface and register; verify step may differ (magic link, OTP), result shape stays compatible.
 */

import { verifyAppleToken } from '../apple';
import { verifyGoogleToken } from '../google';
import { provisionUser } from './provision';
import type { ProvisionResult } from './provision';

/** Provider id for bootstrap handlers. Epic 13 will extend with e.g. 'email' | 'sms'. */
export type BootstrapProviderId = 'apple' | 'google';

/**
 * Single contract for "verify identity and provision user."
 * Given a raw identity token (or future: magic link token / OTP), returns ProvisionResult or throws.
 */
export interface BootstrapHandler {
	verifyAndProvision(token: string): Promise<ProvisionResult>;
}

function createAppleHandler(): BootstrapHandler {
	return {
		async verifyAndProvision(token: string): Promise<ProvisionResult> {
			const payload = await verifyAppleToken(token);
			return provisionUser('apple', payload);
		}
	};
}

function createGoogleHandler(): BootstrapHandler {
	return {
		async verifyAndProvision(token: string): Promise<ProvisionResult> {
			const payload = await verifyGoogleToken(token);
			return provisionUser('google', payload);
		}
	};
}

const handlers: Record<BootstrapProviderId, BootstrapHandler> = {
	apple: createAppleHandler(),
	google: createGoogleHandler()
};

/**
 * Return the bootstrap handler for the given provider.
 * Epic 10 endpoints call getBootstrapHandler('apple'|'google').verifyAndProvision(body.token).
 * Future provider ids (e.g. 'email' | 'sms') will be added in Epic 13.
 */
export function getBootstrapHandler(provider: BootstrapProviderId): BootstrapHandler {
	const handler = handlers[provider];
	if (!handler) {
		throw new Error(`Unknown bootstrap provider: ${provider}`);
	}
	return handler;
}
