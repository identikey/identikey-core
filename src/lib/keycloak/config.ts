import 'dotenv/config';
import { z } from 'zod';

const ConfigSchema = z.object({
	keycloakUrl: z.string().url(),
	keycloakRealm: z.string().default('master'),
	keycloakClientId: z.string(),
	keycloakClientSecret: z.string(),
	logLevel: z.string().default('info')
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(partialEnv?: Partial<Record<keyof Config, string>>): Config {
	const raw = {
		keycloakUrl: partialEnv?.keycloakUrl ?? process.env.KEYCLOAK_URL,
		keycloakRealm: partialEnv?.keycloakRealm ?? process.env.KEYCLOAK_REALM,
		keycloakClientId: partialEnv?.keycloakClientId ?? process.env.KEYCLOAK_CLIENT_ID,
		keycloakClientSecret: partialEnv?.keycloakClientSecret ?? process.env.KEYCLOAK_CLIENT_SECRET,
		logLevel: partialEnv?.logLevel ?? process.env.LOG_LEVEL
	};

	return ConfigSchema.parse(raw);
}
