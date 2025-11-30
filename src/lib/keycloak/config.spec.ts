import { beforeEach, describe, expect, it } from 'vitest';
import type { Config } from './config';
import { loadConfig } from './config';

const ORIGINAL_ENV = { ...process.env };

function resetEnv() {
	process.env = { ...ORIGINAL_ENV };
	delete process.env.KEYCLOAK_URL;
	delete process.env.KEYCLOAK_REALM;
	delete process.env.KEYCLOAK_CLIENT_ID;
	delete process.env.KEYCLOAK_USERNAME;
	delete process.env.KEYCLOAK_PASSWORD;
	delete process.env.LOG_LEVEL;
}

describe('loadConfig', () => {
	beforeEach(() => {
		resetEnv();
	});

	it('loads configuration from environment with sensible defaults', () => {
		process.env.KEYCLOAK_URL = 'https://auth.example.com';
		process.env.KEYCLOAK_USERNAME = 'admin';
		process.env.KEYCLOAK_PASSWORD = 'secret';

		const cfg: Config = loadConfig();

		expect(cfg.keycloakUrl).toBe('https://auth.example.com');
		expect(cfg.keycloakRealm).toBe('master');
		expect(cfg.keycloakClientId).toBe('admin-cli');
		expect(cfg.keycloakUsername).toBe('admin');
		expect(cfg.keycloakPassword).toBe('secret');
		expect(cfg.logLevel).toBe('info');
	});

	it('respects explicit realm and client id from env', () => {
		process.env.KEYCLOAK_URL = 'https://auth.example.com';
		process.env.KEYCLOAK_REALM = 'custom';
		process.env.KEYCLOAK_CLIENT_ID = 'kc-admin';
		process.env.KEYCLOAK_USERNAME = 'admin';
		process.env.KEYCLOAK_PASSWORD = 'secret';
		process.env.LOG_LEVEL = 'debug';

		const cfg = loadConfig();

		expect(cfg.keycloakRealm).toBe('custom');
		expect(cfg.keycloakClientId).toBe('kc-admin');
		expect(cfg.logLevel).toBe('debug');
	});

	it('throws a validation error when required variables are missing', () => {
		// Only URL is provided; username/password missing
		process.env.KEYCLOAK_URL = 'https://auth.example.com';

		expect(() => loadConfig()).toThrowError();
	});

	it('throws when KEYCLOAK_URL is not a valid URL', () => {
		process.env.KEYCLOAK_URL = 'not-a-url';
		process.env.KEYCLOAK_USERNAME = 'admin';
		process.env.KEYCLOAK_PASSWORD = 'secret';

		expect(() => loadConfig()).toThrowError();
	});

	it('supports overriding values via partial env parameter for tests', () => {
		const cfg = loadConfig({
			keycloakUrl: 'https://override.example.com',
			keycloakUsername: 'tester',
			keycloakPassword: 'pwd'
		});

		expect(cfg.keycloakUrl).toBe('https://override.example.com');
		expect(cfg.keycloakUsername).toBe('tester');
		expect(cfg.keycloakPassword).toBe('pwd');
	});
});
