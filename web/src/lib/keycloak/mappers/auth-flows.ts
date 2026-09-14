/**
 * Auth Flow mappers
 *
 * Maps Keycloak AuthenticationFlowRepresentation to IdentiKey LoginFlow domain type.
 */

import type AuthenticationFlowRepresentation from '@keycloak/keycloak-admin-client/lib/defs/authenticationFlowRepresentation';
import type AuthenticationExecutionInfoRepresentation from '@keycloak/keycloak-admin-client/lib/defs/authenticationExecutionInfoRepresentation';
import type { LoginFlow, FlowExecution } from '../types';

/**
 * Map a Keycloak AuthenticationFlowRepresentation to IdentiKey LoginFlow.
 */
export function mapKeycloakFlow(kcFlow: AuthenticationFlowRepresentation): LoginFlow {
	return {
		id: kcFlow.id!,
		alias: kcFlow.alias!,
		description: kcFlow.description,
		providerId: kcFlow.providerId ?? 'basic-flow',
		topLevel: kcFlow.topLevel ?? false,
		builtIn: kcFlow.builtIn ?? false
	};
}

/**
 * Map a Keycloak AuthenticationExecutionInfoRepresentation to IdentiKey FlowExecution.
 */
export function mapKeycloakExecution(
	kcExec: AuthenticationExecutionInfoRepresentation
): FlowExecution {
	return {
		id: kcExec.id!,
		displayName: kcExec.displayName ?? kcExec.alias ?? 'Unknown',
		requirement: (kcExec.requirement as FlowExecution['requirement']) ?? 'DISABLED',
		configurable: kcExec.configurable ?? false,
		providerId: kcExec.providerId,
		level: kcExec.level ?? 0,
		index: kcExec.index ?? 0,
		authenticationFlow: kcExec.authenticationFlow ?? false
	};
}
