import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ url }) => {
	const rawIssuer = process.env.IDENTIKEY_ISSUER || url.origin;
	const issuer = rawIssuer.replace(/\/+$/, '');

	return json(
		{
			issuer,
			jwks_uri: `${issuer}/.well-known/jwks.json`,
			token_endpoint: `${issuer}/api/token/refresh`,
			introspection_endpoint: `${issuer}/api/introspect`,
			id_token_signing_alg_values_supported: ['EdDSA'],
			subject_types_supported: ['public'],
			response_types_supported: ['id_token']
		},
		{
			headers: {
				'Cache-Control': 'public, max-age=3600'
			}
		}
	);
};
