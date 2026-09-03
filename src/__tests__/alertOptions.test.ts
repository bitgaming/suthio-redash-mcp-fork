/**
 * Alert options are stored by Redash as one JSON blob that a write replaces
 * wholesale, so these tests pin down what the server actually sends to
 * /api/alerts — the keys a caller omitted have to survive the round trip.
 */

process.env.REDASH_URL = 'https://redash.example.com';
process.env.REDASH_API_KEY = 'test-api-key';

import { jest } from '@jest/globals';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../index.js';
import type { RedashClient } from '../redashClient.js';

const storedAlert = {
  id: 7,
  name: 'Big win',
  query_id: 2955,
  options: {
    column: 'amount',
    op: '>',
    value: 15000,
    selector: 'first' as const,
    custom_body: 'stored body',
    template: 'legacy body',
    muted: false
  },
  state: 'ok',
  last_triggered_at: null,
  rearm: 60,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z'
};

function connect(client: Partial<RedashClient>) {
  const server = createServer(client as RedashClient);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcp = new Client({ name: 'test', version: '0.0.0' });
  return Promise.all([mcp.connect(clientTransport), server.connect(serverTransport)]).then(() => mcp);
}

describe('create_alert', () => {
  it('sends a selector so notifications can render', async () => {
    const createAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const mcp = await connect({ createAlert });

    await mcp.callTool({
      name: 'create_alert',
      arguments: { name: 'Big win', query_id: 2955, options: { column: 'amount', op: '>', value: 15000 } }
    });

    expect(createAlert).toHaveBeenCalledWith(
      expect.objectContaining({ options: expect.objectContaining({ selector: 'first' }) })
    );
  });

  it('passes through the options it accepts', async () => {
    const createAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const mcp = await connect({ createAlert });

    const options = {
      column: 'amount',
      op: '>=',
      value: 15000,
      selector: 'max' as const,
      custom_subject: 'subject',
      custom_body: 'body'
    };
    await mcp.callTool({ name: 'create_alert', arguments: { name: 'Big win', query_id: 2955, options } });

    expect(createAlert).toHaveBeenCalledWith(expect.objectContaining({ options }));
  });
});

describe('update_alert', () => {
  it('keeps options the caller did not mention, including ones the schema omits', async () => {
    const getAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const updateAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const mcp = await connect({ getAlert, updateAlert });

    await mcp.callTool({
      name: 'update_alert',
      arguments: { alertId: 7, options: { value: 20000 } }
    });

    expect(updateAlert).toHaveBeenCalledWith(7, {
      options: {
        column: 'amount',
        op: '>',
        value: 20000,
        selector: 'first',
        custom_body: 'stored body',
        template: 'legacy body',
        muted: false
      }
    });
  });

  it('does not read the alert when only non-option fields change', async () => {
    const getAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const updateAlert = jest.fn<any>().mockResolvedValue(storedAlert);
    const mcp = await connect({ getAlert, updateAlert });

    await mcp.callTool({ name: 'update_alert', arguments: { alertId: 7, query_id: 3000 } });

    expect(getAlert).not.toHaveBeenCalled();
    expect(updateAlert).toHaveBeenCalledWith(7, { query_id: 3000 });
  });
});
