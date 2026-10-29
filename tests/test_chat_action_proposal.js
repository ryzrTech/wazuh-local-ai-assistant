const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

process.env.ASSISTANT_PROXY_TOKEN = 'x'.repeat(32);
process.env.ASSISTANT_ADMIN_TOKEN = 'a'.repeat(32);
const originalLoad = Module._load;
Module._load = function (name, parent, isMain) {
  if (name === '@osd/config-schema') return { schema: { object: () => ({}), string: () => ({}), number: () => ({}), boolean: () => ({}), maybe: () => ({}) } };
  return originalLoad(name, parent, isMain);
};
const { proposeWazuhAction } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function main() {
  let saved = 0;
  const backend = http.createServer(async (request, response) => {
    assert.equal(request.headers['x-assistant-admin-token'], process.env.ASSISTANT_ADMIN_TOKEN);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(body.agent_id, '001');
    saved++;
    response.writeHead(201, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ id: '12345678-1234-1234-1234-123456789abc', ...body, expires_at: '2026-01-01T00:00:00Z' }));
  });
  await new Promise((resolve) => backend.listen(8765, '127.0.0.1', resolve));
  let alertIp = '203.0.113.5';
  const context = { core: { opensearch: { client: { asCurrentUser: { transport: { request: async () => ({ body: {
    _source: { agent: { id: '001' }, data: { srcip: alertIp } },
  } }) } } } } }, wazuh_core: {
    manageHosts: { get: async () => [{ id: 'host' }], isEnabledAuthWithRunAs: () => true },
    api: { client: { asCurrentUser: { authenticate: async () => 'scoped-token' } } },
    serverAPIClient: { _request: async () => ({ data: { data: { affected_items: [{ id: '001' }] } } }) },
  } };
  const id = '12345678-1234-1234-1234-123456789abc';
  const args = JSON.stringify({ action: 'block_ip', agent_id: '001', target_ip: '203.0.113.5',
    evidence_ref: 'wazuh-alerts-example/1', reason: 'Block observed malicious source IP' });
  try {
    await assert.rejects(() => proposeWazuhAction(context, 'a'.repeat(64), false, id, args), { statusCode: 403 });
    alertIp = '203.0.113.6';
    await assert.rejects(() => proposeWazuhAction(context, 'a'.repeat(64), true, id, args), /must match/);
    assert.equal(saved, 0);
    alertIp = '203.0.113.5';
    const proposal = await proposeWazuhAction(context, 'a'.repeat(64), true, id, args);
    assert.equal(proposal.data.action, 'block_ip');
    assert.match(proposal.data.next_step, /Nothing was executed/);
    assert.equal(saved, 1);
    process.stdout.write('chat response proposal requires admin and matching alert evidence: ok\n');
  } finally { backend.close(); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
