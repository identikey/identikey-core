import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type AuthenticationFlowRepresentation from '@keycloak/keycloak-admin-client/lib/defs/authenticationFlowRepresentation';
import type AuthenticationExecutionInfoRepresentation from '@keycloak/keycloak-admin-client/lib/defs/authenticationExecutionInfoRepresentation';

import { AuthFlowService } from './auth-flows';
import { ErrorCodes, IdentiKeyError } from '../errors';

// Mock logger to suppress output during tests
vi.mock('../logger', () => ({
	logger: {
		debug: vi.fn(),
		info: vi.fn(),
		error: vi.fn()
	}
}));

function createMockClient(): {
	client: KcAdminClient;
	authMgmt: {
		getFlows: Mock;
		getExecutions: Mock;
		copyFlow: Mock;
	};
} {
	const authMgmtMock = {
		getFlows: vi.fn(),
		getExecutions: vi.fn(),
		copyFlow: vi.fn()
	};

	return {
		client: { authenticationManagement: authMgmtMock } as unknown as KcAdminClient,
		authMgmt: authMgmtMock
	};
}

const mockBrowserFlow: AuthenticationFlowRepresentation = {
	id: 'flow-browser-123',
	alias: 'browser',
	description: 'Browser-based authentication',
	providerId: 'basic-flow',
	topLevel: true,
	builtIn: true
};

const mockDirectGrantFlow: AuthenticationFlowRepresentation = {
	id: 'flow-direct-456',
	alias: 'direct grant',
	description: 'Direct access grants',
	providerId: 'basic-flow',
	topLevel: true,
	builtIn: true
};

const mockCustomFlow: AuthenticationFlowRepresentation = {
	id: 'flow-custom-789',
	alias: 'browser-custom',
	description: 'Custom browser flow',
	providerId: 'basic-flow',
	topLevel: true,
	builtIn: false
};

const mockExecutions: AuthenticationExecutionInfoRepresentation[] = [
	{
		id: 'exec-1',
		displayName: 'Cookie',
		requirement: 'ALTERNATIVE',
		configurable: false,
		providerId: 'auth-cookie',
		level: 0,
		index: 0,
		authenticationFlow: false
	},
	{
		id: 'exec-2',
		displayName: 'forms',
		requirement: 'ALTERNATIVE',
		configurable: false,
		level: 0,
		index: 1,
		authenticationFlow: true
	},
	{
		id: 'exec-3',
		displayName: 'Username Password Form',
		requirement: 'REQUIRED',
		configurable: false,
		providerId: 'auth-username-password-form',
		level: 1,
		index: 0,
		authenticationFlow: false
	}
];

describe('AuthFlowService', () => {
	let service: AuthFlowService;
	let mocks: ReturnType<typeof createMockClient>;

	beforeEach(() => {
		mocks = createMockClient();
		service = new AuthFlowService(mocks.client);
	});

	describe('list', () => {
		it('returns all mapped flows', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow, mockDirectGrantFlow]);

			const flows = await service.list();

			expect(mocks.authMgmt.getFlows).toHaveBeenCalled();
			expect(flows).toHaveLength(2);
			expect(flows[0]).toEqual({
				id: 'flow-browser-123',
				alias: 'browser',
				description: 'Browser-based authentication',
				providerId: 'basic-flow',
				topLevel: true,
				builtIn: true
			});
		});

		it('handles empty flow list', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([]);

			const flows = await service.list();

			expect(flows).toHaveLength(0);
		});

		it('wraps errors in IdentiKeyError', async () => {
			mocks.authMgmt.getFlows.mockRejectedValue(new Error('Network error'));

			await expect(service.list()).rejects.toBeInstanceOf(IdentiKeyError);
			await expect(service.list()).rejects.toMatchObject({
				message: 'Failed to list authentication flows',
				code: ErrorCodes.CONNECTION_FAILED
			});
		});
	});

	describe('get', () => {
		it('returns single flow by alias', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow, mockDirectGrantFlow]);

			const flow = await service.get('browser');

			expect(flow.alias).toBe('browser');
			expect(flow.builtIn).toBe(true);
		});

		it('throws AUTH_FLOW_NOT_FOUND for unknown alias', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow]);

			await expect(service.get('nonexistent')).rejects.toMatchObject({
				code: ErrorCodes.AUTH_FLOW_NOT_FOUND,
				message: 'Authentication flow not found: nonexistent'
			});
		});

		it('wraps 404 as AUTH_FLOW_NOT_FOUND', async () => {
			const err = Object.assign(new Error('Not found'), { response: { status: 404 } });
			mocks.authMgmt.getFlows.mockRejectedValue(err);

			await expect(service.get('browser')).rejects.toMatchObject({
				code: ErrorCodes.AUTH_FLOW_NOT_FOUND
			});
		});
	});

	describe('listExecutions', () => {
		it('returns mapped executions for flow', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow]);
			mocks.authMgmt.getExecutions.mockResolvedValue(mockExecutions);

			const executions = await service.listExecutions('browser');

			expect(mocks.authMgmt.getExecutions).toHaveBeenCalledWith({ flow: 'browser' });
			expect(executions).toHaveLength(3);
			expect(executions[0]).toEqual({
				id: 'exec-1',
				displayName: 'Cookie',
				requirement: 'ALTERNATIVE',
				configurable: false,
				providerId: 'auth-cookie',
				level: 0,
				index: 0,
				authenticationFlow: false
			});
		});

		it('sorts executions by level then index', async () => {
			const unorderedExecutions = [
				{ id: 'e3', level: 1, index: 0, displayName: 'C' },
				{ id: 'e1', level: 0, index: 0, displayName: 'A' },
				{ id: 'e4', level: 1, index: 1, displayName: 'D' },
				{ id: 'e2', level: 0, index: 1, displayName: 'B' }
			];
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow]);
			mocks.authMgmt.getExecutions.mockResolvedValue(unorderedExecutions);

			const executions = await service.listExecutions('browser');

			// Should be sorted: level 0 (index 0, 1), then level 1 (index 0, 1)
			expect(executions.map((e) => e.id)).toEqual(['e1', 'e2', 'e3', 'e4']);
		});

		it('throws AUTH_FLOW_NOT_FOUND for unknown flow', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow]);

			await expect(service.listExecutions('nonexistent')).rejects.toMatchObject({
				code: ErrorCodes.AUTH_FLOW_NOT_FOUND
			});
		});
	});

	describe('copy', () => {
		it('copies flow and returns new flow', async () => {
			mocks.authMgmt.getFlows
				.mockResolvedValueOnce([mockBrowserFlow]) // First call: verify source exists
				.mockResolvedValueOnce([mockBrowserFlow]) // Second call: check target doesn't exist
				.mockResolvedValueOnce([mockBrowserFlow, mockCustomFlow]); // Third call: get new flow
			mocks.authMgmt.copyFlow.mockResolvedValue(undefined);

			const newFlow = await service.copy('browser', 'browser-custom');

			expect(mocks.authMgmt.copyFlow).toHaveBeenCalledWith(
				{ flow: 'browser' },
				{ newName: 'browser-custom' }
			);
			expect(newFlow.alias).toBe('browser-custom');
			expect(newFlow.builtIn).toBe(false);
		});

		it('throws AUTH_FLOW_NOT_FOUND for unknown source', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow]);

			await expect(service.copy('nonexistent', 'new-flow')).rejects.toMatchObject({
				code: ErrorCodes.AUTH_FLOW_NOT_FOUND
			});
		});

		it('throws INVALID_INPUT when target alias already exists', async () => {
			mocks.authMgmt.getFlows.mockResolvedValue([mockBrowserFlow, mockCustomFlow]);

			await expect(service.copy('browser', 'browser-custom')).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT,
				message: "Flow with alias 'browser-custom' already exists"
			});
		});

		it('throws INVALID_INPUT when new alias is empty', async () => {
			await expect(service.copy('browser', '')).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT,
				message: 'New alias is required'
			});
		});

		it('throws INVALID_INPUT for whitespace-only alias', async () => {
			await expect(service.copy('browser', '   ')).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT
			});
		});
	});

	describe('error classification', () => {
		it('classifies 401 as UNAUTHORIZED', async () => {
			const err = Object.assign(new Error('Unauthorized'), { response: { status: 401 } });
			mocks.authMgmt.getFlows.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.UNAUTHORIZED
			});
		});

		it('classifies 403 as UNAUTHORIZED', async () => {
			const err = Object.assign(new Error('Forbidden'), { response: { status: 403 } });
			mocks.authMgmt.getFlows.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.UNAUTHORIZED
			});
		});

		it('classifies network errors as CONNECTION_FAILED', async () => {
			const err = Object.assign(new Error('Connection refused'), { code: 'ECONNREFUSED' });
			mocks.authMgmt.getFlows.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.CONNECTION_FAILED
			});
		});

		it('classifies ENOTFOUND as CONNECTION_FAILED', async () => {
			const err = Object.assign(new Error('DNS lookup failed'), { code: 'ENOTFOUND' });
			mocks.authMgmt.getFlows.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.CONNECTION_FAILED
			});
		});
	});
});

describe('getAuthFlowService factory', () => {
	it('factory function exists and is callable', async () => {
		const { getAuthFlowService } = await import('./index');

		expect(getAuthFlowService).toBeDefined();
		expect(typeof getAuthFlowService).toBe('function');
	});
});
