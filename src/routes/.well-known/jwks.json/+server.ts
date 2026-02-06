import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { getSigningKey, getPublicKeyJwk } from '$lib/auth/jwt';

export const GET: RequestHandler = async () => {
	try {
		const keyPair = getSigningKey();
		const publicKeyJwk = await getPublicKeyJwk(keyPair);

		return json(
			{ keys: [publicKeyJwk] },
			{
				headers: {
					'Cache-Control': 'public, max-age=3600'
				}
			}
		);
	} catch {
		return json(
			{ error: 'Service Unavailable' },
			{ status: 503 }
		);
	}
};
