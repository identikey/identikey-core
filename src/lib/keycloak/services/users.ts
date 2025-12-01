/**
 * UserService — Core user operations
 *
 * Wraps Keycloak Admin Client user operations and exposes IdentiKey domain types.
 * All errors are wrapped in IdentiKeyError with appropriate error codes.
 */

import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type { User, CreateUserInput, UpdateUserInput, ListOptions, Credential } from '../types';
import { ErrorCodes, IdentiKeyError } from '../errors';
import { mapKeycloakUser, mapKeycloakCredential } from '../mappers/users';
import { logger } from '../logger';

export class UserService {
	constructor(private client: KcAdminClient) {}

	/**
	 * List users with pagination (FR5)
	 */
	async list(options?: ListOptions): Promise<User[]> {
		try {
			const kcUsers = await this.client.users.find({
				max: options?.max ?? 100,
				first: options?.offset ?? 0
			});

			// Fetch groups for each user to populate guilds
			const users = await Promise.all(
				kcUsers.map(async (kcUser) => {
					const groups = await this.client.users.listGroups({ id: kcUser.id! });
					return mapKeycloakUser(kcUser, groups);
				})
			);

			logger.debug({ count: users.length }, 'Listed users');
			return users;
		} catch (error) {
			throw this.wrapError(error, 'Failed to list users');
		}
	}

	/**
	 * Search users by username, email, firstName, lastName (FR6)
	 */
	async search(query: string, options?: ListOptions): Promise<User[]> {
		try {
			const kcUsers = await this.client.users.find({
				search: query,
				max: options?.max ?? 100,
				first: options?.offset ?? 0
			});

			const users = await Promise.all(
				kcUsers.map(async (kcUser) => {
					const groups = await this.client.users.listGroups({ id: kcUser.id! });
					return mapKeycloakUser(kcUser, groups);
				})
			);

			logger.debug({ query, count: users.length }, 'Searched users');
			return users;
		} catch (error) {
			throw this.wrapError(error, 'Failed to search users');
		}
	}

	/**
	 * Get user by ID (FR7)
	 */
	async get(id: string): Promise<User> {
		try {
			const kcUser = await this.client.users.findOne({ id });
			if (!kcUser) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			const groups = await this.client.users.listGroups({ id });
			logger.debug({ userId: id }, 'Fetched user');
			return mapKeycloakUser(kcUser, groups);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get user: ${id}`);
		}
	}

	/**
	 * Create a new user (FR8)
	 */
	async create(data: CreateUserInput): Promise<User> {
		if (!data.username) {
			throw new IdentiKeyError('Username is required', ErrorCodes.INVALID_INPUT);
		}

		try {
			const response = await this.client.users.create({
				username: data.username,
				email: data.email,
				firstName: data.firstName,
				lastName: data.lastName,
				enabled: data.enabled ?? true
			});

			// Extract ID from Location header (Keycloak returns { id } on create)
			const userId = response.id;
			logger.info({ userId, username: data.username }, 'Created user');
			return this.get(userId);
		} catch (error) {
			// Keycloak returns 409 for duplicate username
			if (this.isConflictError(error)) {
				throw new IdentiKeyError(
					`User with username '${data.username}' already exists`,
					ErrorCodes.INVALID_INPUT
				);
			}
			throw this.wrapError(error, 'Failed to create user');
		}
	}

	/**
	 * Update user attributes (FR9)
	 */
	async update(id: string, data: UpdateUserInput): Promise<User> {
		try {
			// Verify user exists first
			const existing = await this.client.users.findOne({ id });
			if (!existing) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			await this.client.users.update(
				{ id },
				{
					username: data.username ?? existing.username,
					email: data.email ?? existing.email,
					firstName: data.firstName ?? existing.firstName,
					lastName: data.lastName ?? existing.lastName,
					enabled: data.enabled ?? existing.enabled
				}
			);

			logger.info({ userId: id }, 'Updated user');
			return this.get(id);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to update user: ${id}`);
		}
	}

	/**
	 * Delete user (FR10)
	 */
	async delete(id: string): Promise<void> {
		try {
			// Verify user exists first
			const existing = await this.client.users.findOne({ id });
			if (!existing) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			await this.client.users.del({ id });
			logger.info({ userId: id }, 'Deleted user');
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to delete user: ${id}`);
		}
	}

	/**
	 * Reset user password (FR11)
	 */
	async resetPassword(id: string, password: string, temporary = false): Promise<void> {
		if (!password) {
			throw new IdentiKeyError('Password is required', ErrorCodes.INVALID_INPUT);
		}

		try {
			// Verify user exists first
			const existing = await this.client.users.findOne({ id });
			if (!existing) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			await this.client.users.resetPassword({
				id,
				credential: {
					type: 'password',
					value: password,
					temporary
				}
			});

			logger.info({ userId: id, temporary }, 'Reset user password');
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to reset password for user: ${id}`);
		}
	}

	/**
	 * Get user credentials (FR12)
	 */
	async getCredentials(id: string): Promise<Credential[]> {
		try {
			// Verify user exists first
			const existing = await this.client.users.findOne({ id });
			if (!existing) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			const kcCredentials = await this.client.users.getCredentials({ id });
			logger.debug({ userId: id, count: kcCredentials.length }, 'Fetched user credentials');
			return kcCredentials.map(mapKeycloakCredential);
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to get credentials for user: ${id}`);
		}
	}

	/**
	 * Delete a specific credential from user (FR13)
	 */
	async deleteCredential(id: string, credentialId: string): Promise<void> {
		try {
			// Verify user exists first
			const existing = await this.client.users.findOne({ id });
			if (!existing) {
				throw new IdentiKeyError(`User not found: ${id}`, ErrorCodes.USER_NOT_FOUND);
			}

			await this.client.users.deleteCredential({ id, credentialId });
			logger.info({ userId: id, credentialId }, 'Deleted user credential');
		} catch (error) {
			if (error instanceof IdentiKeyError) throw error;
			throw this.wrapError(error, `Failed to delete credential ${credentialId} for user: ${id}`);
		}
	}

	/**
	 * Wrap unknown errors in IdentiKeyError with appropriate codes
	 */
	private wrapError(error: unknown, message: string): IdentiKeyError {
		const err = error instanceof Error ? error : new Error(String(error));

		// Check for HTTP status codes in the error
		const maybeStatus = (error as { response?: { status?: number } }).response?.status;

		if (maybeStatus === 401 || maybeStatus === 403) {
			return new IdentiKeyError(message, ErrorCodes.UNAUTHORIZED, err);
		}

		if (maybeStatus === 404) {
			return new IdentiKeyError(message, ErrorCodes.USER_NOT_FOUND, err);
		}

		// Network/connectivity errors
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

	/**
	 * Check if error is a 409 Conflict
	 */
	private isConflictError(error: unknown): boolean {
		return (error as { response?: { status?: number } }).response?.status === 409;
	}
}
