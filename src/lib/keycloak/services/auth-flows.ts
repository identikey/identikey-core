/**
 * AuthFlowService — Core authentication flow operations
 *
 * Wraps Keycloak Admin Client authenticationManagement operations.
 * All errors are wrapped in IdentiKeyError with appropriate error codes.
 */

import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type { LoginFlow, FlowExecution } from '../types';
import { ErrorCodes, IdentiKeyError } from '../errors';
import { mapKeycloakFlow, mapKeycloakExecution } from '../mappers/auth-flows';
import { logger } from '../logger';

export class AuthFlowService {
	constructor(private client: KcAdminClient) {}

	/**
	 * List all authentication flows (FR34)
	 */
	async list(): Promise<LoginFlow[]> {
		try {
			const kcFlows = await this.client.authenticationManagement.getFlows();
			const flows = kcFlows.map(mapKeycloakFlow);
			logger.debug({ count: flows.length }, 'Listed auth flows');
			return flows;
		} catch (error) {
			throw this.wrapError(error, 'Failed to list authentication flows');
		}
	}

	/**
	 * Get a single flow by alias (FR35)
	 */
	async get(flowAlias: string): Promise<LoginFlow> {
		try {
			const kcFlows = await this.client.authenticationManagement.getFlows();
			const kcFlow = kcFlows.find((f) => f.alias === flowAlias);

			if (!kcFlow) {
				throw new IdentiKeyError(
					`Authentication flow not found: ${flowAlias}`,
					ErrorCodes.AUTH_FLOW_NOT_FOUND
				);
			}

			logger.debug({ flowAlias }, 'Fetched auth flow');
			return mapKeycloakFlow(kcFlow);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get authentication flow: ${flowAlias}`);
		}
	}

	/**
	 * List executions (steps) within a flow (FR36)
	 * Returns executions ordered by level + index (hierarchy preserved)
	 */
	async listExecutions(flowAlias: string): Promise<FlowExecution[]> {
		try {
			// Verify flow exists first
			await this.get(flowAlias);

			const kcExecutions = await this.client.authenticationManagement.getExecutions({
				flow: flowAlias
			});

			const executions = kcExecutions.map(mapKeycloakExecution);

			// Sort by level then index to maintain hierarchy
			executions.sort((a, b) => {
				if (a.level !== b.level) return a.level - b.level;
				return a.index - b.index;
			});

			logger.debug({ flowAlias, count: executions.length }, 'Listed flow executions');
			return executions;
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to list executions for flow: ${flowAlias}`);
		}
	}

	/**
	 * Copy a flow to a new alias (FR40)
	 * Built-in flows can't be modified — copy them first.
	 */
	async copy(sourceAlias: string, newAlias: string): Promise<LoginFlow> {
		if (!newAlias || newAlias.trim() === '') {
			throw new IdentiKeyError('New alias is required', ErrorCodes.INVALID_INPUT);
		}

		try {
			// Verify source exists
			await this.get(sourceAlias);

			// Check if target alias already exists
			const kcFlows = await this.client.authenticationManagement.getFlows();
			const existing = kcFlows.find((f) => f.alias === newAlias);
			if (existing) {
				throw new IdentiKeyError(
					`Flow with alias '${newAlias}' already exists`,
					ErrorCodes.INVALID_INPUT
				);
			}

			await this.client.authenticationManagement.copyFlow(
				{ flow: sourceAlias },
				{ newName: newAlias }
			);

			logger.info({ sourceAlias, newAlias }, 'Copied auth flow');
			return this.get(newAlias);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to copy flow '${sourceAlias}' to '${newAlias}'`);
		}
	}

	/**
	 * Wrap unknown errors in IdentiKeyError with appropriate codes
	 */
	private wrapError(error: unknown, message: string): IdentiKeyError {
		const err = error instanceof Error ? error : new Error(String(error));
		const maybeStatus = (error as { response?: { status?: number } }).response?.status;

		if (maybeStatus === 401 || maybeStatus === 403) {
			return new IdentiKeyError(message, ErrorCodes.UNAUTHORIZED, err);
		}

		if (maybeStatus === 404) {
			return new IdentiKeyError(message, ErrorCodes.AUTH_FLOW_NOT_FOUND, err);
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
