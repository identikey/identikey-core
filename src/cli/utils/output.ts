/**
 * CLI Output Utilities
 *
 * Formatters for table and JSON output in CLI commands.
 */

import type { User, Credential } from '../../lib/keycloak/types';
import { IdentiKeyError } from '../../lib/keycloak/errors';

/**
 * Print data as formatted JSON to stdout
 */
export function printJson(data: unknown): void {
	// eslint-disable-next-line no-console
	console.log(JSON.stringify(data, null, 2));
}

/**
 * Print a simple table of users
 * Columns: id, username, email, enabled
 */
export function printUsersTable(users: User[]): void {
	if (users.length === 0) {
		// eslint-disable-next-line no-console
		console.log('No users found.');
		return;
	}

	// Calculate column widths
	const idWidth = Math.max(4, ...users.map((u) => u.id.length));
	const usernameWidth = Math.max(8, ...users.map((u) => u.username.length));
	const emailWidth = Math.max(5, ...users.map((u) => (u.email ?? '').length));

	const header = [
		'ID'.padEnd(idWidth),
		'USERNAME'.padEnd(usernameWidth),
		'EMAIL'.padEnd(emailWidth),
		'ENABLED'
	].join('  ');

	const separator = '-'.repeat(header.length);

	// eslint-disable-next-line no-console
	console.log(header);
	// eslint-disable-next-line no-console
	console.log(separator);

	for (const user of users) {
		const row = [
			user.id.padEnd(idWidth),
			user.username.padEnd(usernameWidth),
			(user.email ?? '').padEnd(emailWidth),
			user.enabled ? 'yes' : 'no'
		].join('  ');
		// eslint-disable-next-line no-console
		console.log(row);
	}

	// eslint-disable-next-line no-console
	console.log(`\n${users.length} user(s) found.`);
}

/**
 * Print full user details
 */
export function printUserDetails(user: User): void {
	// eslint-disable-next-line no-console
	console.log(`User: ${user.username}`);
	// eslint-disable-next-line no-console
	console.log(`  ID:         ${user.id}`);
	// eslint-disable-next-line no-console
	console.log(`  Email:      ${user.email ?? '(not set)'}`);
	// eslint-disable-next-line no-console
	console.log(`  First Name: ${user.firstName ?? '(not set)'}`);
	// eslint-disable-next-line no-console
	console.log(`  Last Name:  ${user.lastName ?? '(not set)'}`);
	// eslint-disable-next-line no-console
	console.log(`  Enabled:    ${user.enabled ? 'yes' : 'no'}`);
	if (user.createdTimestamp) {
		// eslint-disable-next-line no-console
		console.log(`  Created:    ${new Date(user.createdTimestamp).toISOString()}`);
	}
	if (user.guilds.length > 0) {
		// eslint-disable-next-line no-console
		console.log(`  Guilds:     ${user.guilds.join(', ')}`);
	}
}

/**
 * Print credentials table
 */
export function printCredentialsTable(credentials: Credential[]): void {
	if (credentials.length === 0) {
		// eslint-disable-next-line no-console
		console.log('No credentials found.');
		return;
	}

	const idWidth = Math.max(2, ...credentials.map((c) => c.id.length));
	const typeWidth = Math.max(4, ...credentials.map((c) => c.type.length));
	const labelWidth = Math.max(5, ...credentials.map((c) => (c.userLabel ?? '').length));

	const header = [
		'ID'.padEnd(idWidth),
		'TYPE'.padEnd(typeWidth),
		'LABEL'.padEnd(labelWidth),
		'CREATED'
	].join('  ');

	const separator = '-'.repeat(header.length);

	// eslint-disable-next-line no-console
	console.log(header);
	// eslint-disable-next-line no-console
	console.log(separator);

	for (const cred of credentials) {
		const created = cred.createdDate ? new Date(cred.createdDate).toISOString().split('T')[0] : '';
		const row = [
			cred.id.padEnd(idWidth),
			cred.type.padEnd(typeWidth),
			(cred.userLabel ?? '').padEnd(labelWidth),
			created
		].join('  ');
		// eslint-disable-next-line no-console
		console.log(row);
	}

	// eslint-disable-next-line no-console
	console.log(`\n${credentials.length} credential(s) found.`);
}

/**
 * Print an error message to stderr
 * Formats IdentiKeyError with code, otherwise prints raw message
 */
export function printError(error: unknown): void {
	if (error instanceof IdentiKeyError) {
		// eslint-disable-next-line no-console
		console.error(`Error [${error.code}]: ${error.message}`);
	} else if (error instanceof Error) {
		// eslint-disable-next-line no-console
		console.error(`Error: ${error.message}`);
	} else {
		// eslint-disable-next-line no-console
		console.error(`Error: ${String(error)}`);
	}
}

/**
 * Print success message
 */
export function printSuccess(message: string): void {
	// eslint-disable-next-line no-console
	console.log(`✓ ${message}`);
}
