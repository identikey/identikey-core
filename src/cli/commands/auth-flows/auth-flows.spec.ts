/**
 * Tests for CLI auth-flows commands
 *
 * Tests argument parsing, output formatting, and error handling.
 * Mocks AuthFlowService to test CLI command logic in isolation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { LoginFlow, FlowExecution } from '../../../lib/keycloak/types';
import { IdentiKeyError, ErrorCodes } from '../../../lib/keycloak/errors';

// Mock the getAuthFlowService module
vi.mock('../../../lib/keycloak/services', () => ({
	getAuthFlowService: vi.fn()
}));

import { getAuthFlowService } from '../../../lib/keycloak/services';

// Sample test data
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

const mockFlows: LoginFlow[] = [mockBrowserFlow, mockCustomFlow];

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

describe('CLI Auth Flows Commands - Output Utilities', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	describe('printFlowsTable', () => {
		it('should print table with expected columns', async () => {
			const { printFlowsTable } = await import('../../utils/output');
			printFlowsTable(mockFlows);

			const calls = consoleSpy.mock.calls.map((c) => c[0]);
			const header = calls[0];

			expect(header).toContain('ALIAS');
			expect(header).toContain('PROVIDER');
			expect(header).toContain('BUILTIN');
		});

		it('should include flow data in output', async () => {
			const { printFlowsTable } = await import('../../utils/output');
			printFlowsTable(mockFlows);

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
			expect(allOutput).toContain('browser');
			expect(allOutput).toContain('browser-custom');
			expect(allOutput).toContain('basic-flow');
		});

		it('should show count at end', async () => {
			const { printFlowsTable } = await import('../../utils/output');
			printFlowsTable(mockFlows);

			const lastCall = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1][0];
			expect(lastCall).toContain('2 flow(s) found');
		});

		it('should handle empty list', async () => {
			const { printFlowsTable } = await import('../../utils/output');
			printFlowsTable([]);

			expect(consoleSpy).toHaveBeenCalledWith('No authentication flows found.');
		});
	});

	describe('printFlowDetails', () => {
		it('should print all flow properties', async () => {
			const { printFlowDetails } = await import('../../utils/output');
			printFlowDetails(mockBrowserFlow);

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
			expect(allOutput).toContain('browser');
			expect(allOutput).toContain('flow-browser-123');
			expect(allOutput).toContain('Browser-based authentication');
			expect(allOutput).toContain('basic-flow');
		});
	});

	describe('printExecutionsTable', () => {
		it('should show flow alias in header', async () => {
			const { printExecutionsTable } = await import('../../utils/output');
			printExecutionsTable('browser', mockExecutions);

			const firstCall = consoleSpy.mock.calls[0][0];
			expect(firstCall).toContain('browser');
		});

		it('should indent nested executions', async () => {
			const { printExecutionsTable } = await import('../../utils/output');
			printExecutionsTable('browser', mockExecutions);

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
			// Level 1 execution should have 2-space indent
			expect(allOutput).toContain('Username Password Form');
		});

		it('should show count at end', async () => {
			const { printExecutionsTable } = await import('../../utils/output');
			printExecutionsTable('browser', mockExecutions);

			const lastCall = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1][0];
			expect(lastCall).toContain('3 execution(s)');
		});
	});
});

describe('CLI Auth Flows Commands - list', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;
	let mockService: {
		list: ReturnType<typeof vi.fn>;
		get: ReturnType<typeof vi.fn>;
		listExecutions: ReturnType<typeof vi.fn>;
		copy: ReturnType<typeof vi.fn>;
	};

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		mockService = {
			list: vi.fn(),
			get: vi.fn(),
			listExecutions: vi.fn(),
			copy: vi.fn()
		};

		vi.mocked(getAuthFlowService).mockResolvedValue(mockService as never);
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	it('should call list and print table', async () => {
		mockService.list.mockResolvedValue(mockFlows);

		const { listCommand } = await import('./list');
		await listCommand.run!({ args: {}, rawArgs: [], cmd: listCommand });

		expect(mockService.list).toHaveBeenCalled();
		const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
		expect(allOutput).toContain('browser');
	});

	it('should output JSON when --json flag is set', async () => {
		mockService.list.mockResolvedValue(mockFlows);

		const { listCommand } = await import('./list');
		await listCommand.run!({ args: { json: true }, rawArgs: [], cmd: listCommand });

		const output = consoleSpy.mock.calls[0][0];
		const parsed = JSON.parse(output);
		expect(parsed).toHaveLength(2);
		expect(parsed[0].alias).toBe('browser');
	});

	it('should handle errors', async () => {
		mockService.list.mockRejectedValue(
			new IdentiKeyError('Connection failed', ErrorCodes.CONNECTION_FAILED)
		);

		const { listCommand } = await import('./list');
		await listCommand.run!({ args: {}, rawArgs: [], cmd: listCommand });

		expect(errorSpy).toHaveBeenCalled();
		expect(errorSpy.mock.calls[0][0]).toContain('CONNECTION_FAILED');
	});
});

describe('CLI Auth Flows Commands - get', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;
	let mockService: {
		list: ReturnType<typeof vi.fn>;
		get: ReturnType<typeof vi.fn>;
		listExecutions: ReturnType<typeof vi.fn>;
		copy: ReturnType<typeof vi.fn>;
	};

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		mockService = {
			list: vi.fn(),
			get: vi.fn(),
			listExecutions: vi.fn(),
			copy: vi.fn()
		};

		vi.mocked(getAuthFlowService).mockResolvedValue(mockService as never);
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	it('should get flow by alias', async () => {
		mockService.get.mockResolvedValue(mockBrowserFlow);

		const { getCommand } = await import('./get');
		await getCommand.run!({ args: { alias: 'browser' }, rawArgs: [], cmd: getCommand });

		expect(mockService.get).toHaveBeenCalledWith('browser');
		const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
		expect(allOutput).toContain('browser');
	});

	it('should handle not found error', async () => {
		mockService.get.mockRejectedValue(
			new IdentiKeyError('Flow not found', ErrorCodes.AUTH_FLOW_NOT_FOUND)
		);

		const { getCommand } = await import('./get');
		await getCommand.run!({ args: { alias: 'nonexistent' }, rawArgs: [], cmd: getCommand });

		expect(errorSpy).toHaveBeenCalled();
		expect(errorSpy.mock.calls[0][0]).toContain('AUTH_FLOW_NOT_FOUND');
	});
});

describe('CLI Auth Flows Commands - executions', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;
	let mockService: {
		list: ReturnType<typeof vi.fn>;
		get: ReturnType<typeof vi.fn>;
		listExecutions: ReturnType<typeof vi.fn>;
		copy: ReturnType<typeof vi.fn>;
	};

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		mockService = {
			list: vi.fn(),
			get: vi.fn(),
			listExecutions: vi.fn(),
			copy: vi.fn()
		};

		vi.mocked(getAuthFlowService).mockResolvedValue(mockService as never);
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	it('should list executions for flow', async () => {
		mockService.listExecutions.mockResolvedValue(mockExecutions);

		const { executionsCommand } = await import('./executions');
		await executionsCommand.run!({
			args: { alias: 'browser' },
			rawArgs: [],
			cmd: executionsCommand
		});

		expect(mockService.listExecutions).toHaveBeenCalledWith('browser');
		const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
		expect(allOutput).toContain('Cookie');
		expect(allOutput).toContain('forms');
	});

	it('should output JSON with flowAlias when --json flag is set', async () => {
		mockService.listExecutions.mockResolvedValue(mockExecutions);

		const { executionsCommand } = await import('./executions');
		await executionsCommand.run!({
			args: { alias: 'browser', json: true },
			rawArgs: [],
			cmd: executionsCommand
		});

		const output = consoleSpy.mock.calls[0][0];
		const parsed = JSON.parse(output);
		expect(parsed.flowAlias).toBe('browser');
		expect(parsed.executions).toHaveLength(3);
	});
});

describe('CLI Auth Flows Commands - copy', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;
	let mockService: {
		list: ReturnType<typeof vi.fn>;
		get: ReturnType<typeof vi.fn>;
		listExecutions: ReturnType<typeof vi.fn>;
		copy: ReturnType<typeof vi.fn>;
	};

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		mockService = {
			list: vi.fn(),
			get: vi.fn(),
			listExecutions: vi.fn(),
			copy: vi.fn()
		};

		vi.mocked(getAuthFlowService).mockResolvedValue(mockService as never);
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	it('should copy flow and show success', async () => {
		mockService.copy.mockResolvedValue(mockCustomFlow);

		const { copyCommand } = await import('./copy');
		await copyCommand.run!({
			args: { source: 'browser', newAlias: 'browser-custom' },
			rawArgs: [],
			cmd: copyCommand
		});

		expect(mockService.copy).toHaveBeenCalledWith('browser', 'browser-custom');
		const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
		expect(allOutput).toContain('Created flow');
		expect(allOutput).toContain('browser-custom');
	});

	it('should output JSON when --json flag is set', async () => {
		mockService.copy.mockResolvedValue(mockCustomFlow);

		const { copyCommand } = await import('./copy');
		await copyCommand.run!({
			args: { source: 'browser', newAlias: 'browser-custom', json: true },
			rawArgs: [],
			cmd: copyCommand
		});

		const output = consoleSpy.mock.calls[0][0];
		const parsed = JSON.parse(output);
		expect(parsed.copiedFrom).toBe('browser');
		expect(parsed.flow.alias).toBe('browser-custom');
	});

	it('should handle duplicate alias error', async () => {
		mockService.copy.mockRejectedValue(
			new IdentiKeyError('Flow already exists', ErrorCodes.INVALID_INPUT)
		);

		const { copyCommand } = await import('./copy');
		await copyCommand.run!({
			args: { source: 'browser', newAlias: 'browser' },
			rawArgs: [],
			cmd: copyCommand
		});

		expect(errorSpy).toHaveBeenCalled();
		expect(errorSpy.mock.calls[0][0]).toContain('INVALID_INPUT');
	});
});
