import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type { OidcClient, UpdateClientInput, ListOptions } from '../types';
import { ErrorCodes, IdentiKeyError } from '../errors';
import { mapKeycloakClient } from '../mappers/clients';
import { logger } from '../logger';

export class ClientService {
	constructor(private client: KcAdminClient) {}

	async list(options?: ListOptions): Promise<OidcClient[]> {
		try {
			const kcClients = await this.client.clients.find({
				max: options?.max ?? 100,
				first: options?.offset ?? 0,
				search: options?.search !== undefined ? true : undefined,
				clientId: options?.search
			});

			const clients = kcClients.map(mapKeycloakClient);
			logger.debug({ count: clients.length }, 'Listed clients');
			return clients;
		} catch (error) {
			throw this.wrapError(error, 'Failed to list clients');
		}
	}

	async getByClientId(clientId: string): Promise<OidcClient> {
		try {
			const kcClients = await this.client.clients.find({ clientId });
			const match = kcClients.find((c) => c.clientId === clientId);

			if (!match) {
				throw new IdentiKeyError(`Client not found: ${clientId}`, ErrorCodes.APP_NOT_FOUND);
			}

			logger.debug({ clientId }, 'Fetched client');
			return mapKeycloakClient(match);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get client: ${clientId}`);
		}
	}

	async get(id: string): Promise<OidcClient> {
		try {
			const kc = await this.client.clients.findOne({ id });
			if (!kc) {
				throw new IdentiKeyError(`Client not found: ${id}`, ErrorCodes.APP_NOT_FOUND);
			}

			logger.debug({ id }, 'Fetched client by ID');
			return mapKeycloakClient(kc);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get client: ${id}`);
		}
	}

	async update(clientId: string, data: UpdateClientInput): Promise<OidcClient> {
		try {
			const existing = await this.getByClientId(clientId);

			await this.client.clients.update(
				{ id: existing.id },
				{
					clientId: existing.clientId,
					name: data.name ?? existing.name,
					description: data.description ?? existing.description,
					enabled: data.enabled ?? existing.enabled,
					publicClient: data.publicClient ?? existing.publicClient,
					rootUrl: data.rootUrl ?? existing.rootUrl,
					baseUrl: data.baseUrl ?? existing.baseUrl,
					adminUrl: data.adminUrl ?? existing.adminUrl,
					redirectUris: data.redirectUris ?? existing.redirectUris,
					webOrigins: data.webOrigins ?? existing.webOrigins,
					standardFlowEnabled: data.standardFlowEnabled ?? existing.standardFlowEnabled,
					implicitFlowEnabled: data.implicitFlowEnabled ?? existing.implicitFlowEnabled,
					directAccessGrantsEnabled:
						data.directAccessGrantsEnabled ?? existing.directAccessGrantsEnabled,
					serviceAccountsEnabled:
						data.serviceAccountsEnabled ?? existing.serviceAccountsEnabled
				}
			);

			logger.info({ clientId }, 'Updated client');
			return this.get(existing.id);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to update client: ${clientId}`);
		}
	}

	async getSecret(clientId: string): Promise<string | undefined> {
		try {
			const existing = await this.getByClientId(clientId);
			const cred = await this.client.clients.getClientSecret({ id: existing.id });
			return cred.value;
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get secret for client: ${clientId}`);
		}
	}

	private wrapError(error: unknown, message: string): IdentiKeyError {
		const err = error instanceof Error ? error : new Error(String(error));
		const maybeStatus = (error as { response?: { status?: number } }).response?.status;

		if (maybeStatus === 401 || maybeStatus === 403) {
			return new IdentiKeyError(message, ErrorCodes.UNAUTHORIZED, err);
		}
		if (maybeStatus === 404) {
			return new IdentiKeyError(message, ErrorCodes.APP_NOT_FOUND, err);
		}

		const nodeErrorCode = (error as { code?: string }).code;
		const connectivityCodes = new Set([
			'ENOTFOUND',
			'ECONNREFUSED',
			'EAI_AGAIN',
			'ECONNRESET',
			'ETIMEDOUT'
		]);

		if (nodeErrorCode && connectivityCodes.has(nodeErrorCode)) {
			return new IdentiKeyError(message, ErrorCodes.CONNECTION_FAILED, err);
		}

		return new IdentiKeyError(message, ErrorCodes.CONNECTION_FAILED, err);
	}
}
