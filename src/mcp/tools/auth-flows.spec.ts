import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuthFlowService } from '../../lib/keycloak/services/auth-flows';
import type { LoginFlow, FlowExecution } from '../../lib/keycloak/types';
import { ErrorCodes, IdentiKeyError } from '../../lib/keycloak/errors';
import { registerAuthFlowTools } from './auth-flows';

// Mock logger
vi.mock('../../lib/keycloak/logger', () => ({
	logger: {
		debug: vi.fn(),
		info: vi.fn(),
		error: vi.fn()
	}
}));

function createMockServer(): {
	server: McpServer;
	registeredTools: Map<string, { handler: (...args: unknown[]) => Promise<unknown> }>;
} {
	const registeredTools = new Map<string, { handler: (...args: unknown[]) => Promise<unknown> }>();

	const server = {
		registerTool: vi.fn((name: string, _config: unknown, handler: unknown) => {
			registeredTools.set(name, { handler: handler as (...args: unknown[]) => Promise<unknown> });
		})
	} as unknown as McpServer;

	return { server, registeredTools };
}

function createMockAuthFlowService(): {
	service: AuthFlowService;
	mocks: {
		list: Mock;
		get: Mock;
		listExecutions: Mock;
		copy: Mock;
	};
} {
	const mocks = {
		list: vi.fn(),
		get: vi.fn(),
		listExecutions: vi.fn(),
		copy: vi.fn()
	};

	return {
		service: mocks as unknown as AuthFlowService,
		mocks
	};
}

const mockBrowserFlow: LoginFlow = {
	id: 'flow-browser-123',
	alias: 'browser',
	description: 'Browser-based authentication',
	providerId: 'basic-flow',
	topLevel: true,
	builtIn: true
};

const mockCustomFlow: LoginFlow = {
	id: 'flow-custom-456',
	alias: 'browser-custom',
	description: 'Custom browser flow',
	providerId: 'basic-flow',
	topLevel: true,
	builtIn: false
};

const mockExecutions: FlowExecution[] = [
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
	}
];

describe('Auth Flow MCP Tools', () => {
	let mockServer: ReturnType<typeof createMockServer>;
	let mockService: ReturnType<typeof createMockAuthFlowService>;

	beforeEach(() => {
		mockServer = createMockServer();
		mockService = createMockAuthFlowService();
		registerAuthFlowTools(mockServer.server, mockService.service);
	});

	it('registers all 4 auth flow tools', () => {
		expect(mockServer.server.registerTool).toHaveBeenCalledTimes(4);
		expect(mockServer.registeredTools.has('list_login_flows')).toBe(true);
		expect(mockServer.registeredTools.has('get_login_flow')).toBe(true);
		expect(mockServer.registeredTools.has('list_flow_executions')).toBe(true);
		expect(mockServer.registeredTools.has('copy_login_flow')).toBe(true);
	});

	describe('list_login_flows', () => {
		it('returns all flows with count', async () => {
			mockService.mocks.list.mockResolvedValue([mockBrowserFlow, mockCustomFlow]);

			const handler = mockServer.registeredTools.get('list_login_flows')!.handler;
			const result = (await handler({})) as {
				structuredContent: { flows: LoginFlow[]; count: number };
			};

			expect(mockService.mocks.list).toHaveBeenCalled();
			expect(result.structuredContent.flows).toHaveLength(2);
			expect(result.structuredContent.count).toBe(2);
		});

		it('handles empty list', async () => {
			mockService.mocks.list.mockResolvedValue([]);

			const handler = mockServer.registeredTools.get('list_login_flows')!.handler;
			const result = (await handler({})) as {
				structuredContent: { flows: LoginFlow[]; count: number };
			};

			expect(result.structuredContent.flows).toHaveLength(0);
			expect(result.structuredContent.count).toBe(0);
		});

		it('returns structured error on failure', async () => {
			mockService.mocks.list.mockRejectedValue(
				new IdentiKeyError('Connection failed', ErrorCodes.CONNECTION_FAILED)
			);

			const handler = mockServer.registeredTools.get('list_login_flows')!.handler;
			const result = (await handler({})) as { isError: boolean; content: Array<{ text: string }> };

			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('CONNECTION_FAILED');
		});
	});

	describe('get_login_flow', () => {
		it('returns flow by alias', async () => {
			mockService.mocks.get.mockResolvedValue(mockBrowserFlow);

			const handler = mockServer.registeredTools.get('get_login_flow')!.handler;
			const result = (await handler({ flowAlias: 'browser' })) as {
				structuredContent: { flow: LoginFlow };
			};

			expect(mockService.mocks.get).toHaveBeenCalledWith('browser');
			expect(result.structuredContent.flow.alias).toBe('browser');
		});

		it('returns error for unknown flow', async () => {
			mockService.mocks.get.mockRejectedValue(
				new IdentiKeyError('Flow not found', ErrorCodes.AUTH_FLOW_NOT_FOUND)
			);

			const handler = mockServer.registeredTools.get('get_login_flow')!.handler;
			const result = (await handler({ flowAlias: 'nonexistent' })) as {
				isError: boolean;
				content: Array<{ text: string }>;
			};

			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('AUTH_FLOW_NOT_FOUND');
		});
	});

	describe('list_flow_executions', () => {
		it('returns executions for flow', async () => {
			mockService.mocks.listExecutions.mockResolvedValue(mockExecutions);

			const handler = mockServer.registeredTools.get('list_flow_executions')!.handler;
			const result = (await handler({ flowAlias: 'browser' })) as {
				structuredContent: { flowAlias: string; executions: FlowExecution[]; count: number };
			};

			expect(mockService.mocks.listExecutions).toHaveBeenCalledWith('browser');
			expect(result.structuredContent.flowAlias).toBe('browser');
			expect(result.structuredContent.executions).toHaveLength(2);
			expect(result.structuredContent.count).toBe(2);
		});

		it('returns error for unknown flow', async () => {
			mockService.mocks.listExecutions.mockRejectedValue(
				new IdentiKeyError('Flow not found', ErrorCodes.AUTH_FLOW_NOT_FOUND)
			);

			const handler = mockServer.registeredTools.get('list_flow_executions')!.handler;
			const result = (await handler({ flowAlias: 'nonexistent' })) as {
				isError: boolean;
				content: Array<{ text: string }>;
			};

			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('AUTH_FLOW_NOT_FOUND');
		});
	});

	describe('copy_login_flow', () => {
		it('copies flow and returns new flow', async () => {
			mockService.mocks.copy.mockResolvedValue(mockCustomFlow);

			const handler = mockServer.registeredTools.get('copy_login_flow')!.handler;
			const result = (await handler({ sourceAlias: 'browser', newAlias: 'browser-custom' })) as {
				structuredContent: { flow: LoginFlow; copiedFrom: string };
				content: Array<{ text: string }>;
			};

			expect(mockService.mocks.copy).toHaveBeenCalledWith('browser', 'browser-custom');
			expect(result.structuredContent.flow.alias).toBe('browser-custom');
			expect(result.structuredContent.copiedFrom).toBe('browser');
			expect(result.content[0].text).toContain('Created flow');
		});

		it('returns error when source not found', async () => {
			mockService.mocks.copy.mockRejectedValue(
				new IdentiKeyError('Flow not found', ErrorCodes.AUTH_FLOW_NOT_FOUND)
			);

			const handler = mockServer.registeredTools.get('copy_login_flow')!.handler;
			const result = (await handler({ sourceAlias: 'nonexistent', newAlias: 'new-flow' })) as {
				isError: boolean;
				content: Array<{ text: string }>;
			};

			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('AUTH_FLOW_NOT_FOUND');
		});

		it('returns error when target alias exists', async () => {
			mockService.mocks.copy.mockRejectedValue(
				new IdentiKeyError('Flow already exists', ErrorCodes.INVALID_INPUT)
			);

			const handler = mockServer.registeredTools.get('copy_login_flow')!.handler;
			const result = (await handler({ sourceAlias: 'browser', newAlias: 'browser' })) as {
				isError: boolean;
				content: Array<{ text: string }>;
			};

			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('INVALID_INPUT');
		});
	});
});
