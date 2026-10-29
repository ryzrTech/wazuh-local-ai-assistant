const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

process.env.ASSISTANT_POLICY_TOKEN = 'v'.repeat(32);
const originalLoad = Module._load;
Module._load = function (name, parent, isMain) {
  if (name === '@osd/config-schema') return { schema: { object: () => ({}), string: () => ({}), number: () => ({}), boolean: () => ({}), maybe: () => ({}) } };
  return originalLoad(name, parent, isMain);
};
const { proposeAgentSca } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function main() {
  let validated;
  const validator = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    validated = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(request.url, '/validate');
    assert.equal(request.headers['x-policy-token'], process.env.ASSISTANT_POLICY_TOKEN);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ valid: true, proposal_id: '12345678-1234-1234-1234-123456789abc',
      scope: 'All agents in default group', diff: '--- before\n+++ after', validator_output: 'verify-agent-conf: OK', expires_at: '2026-01-01T00:00:00Z' }));
  });
  await new Promise((resolve) => validator.listen(8766, '127.0.0.1', resolve));
  const context = { wazuh_core: {
    manageHosts: { get: async () => [{ id: 'host' }], isEnabledAuthWithRunAs: () => true },
    api: { client: { asCurrentUser: { authenticate: async () => 'scoped-token' } } },
    serverAPIClient: { _request: async (_method, path, options) => {
      assert.equal(path, '/agents');
      assert.equal(options.params.agents_list, '001');
      return { data: { data: { affected_items: [{ id: '001', group: ['default'] }] } } };
    } },
  } };
  const args = JSON.stringify({ agent_id: '001', group: 'default', settings: {
    enabled: 'yes', scan_on_start: 'yes', skip_nfs: 'yes', interval: '12h',
  } });
  try {
    await assert.rejects(() => proposeAgentSca(context, 'a'.repeat(64), false, args), { statusCode: 403 });
    await assert.rejects(() => proposeAgentSca(context, 'a'.repeat(64), true, args.replace('default', '../etc')));
    const result = await proposeAgentSca(context, 'a'.repeat(64), true, args);
    assert.equal(result.count, 1);
    assert.equal(result.data.proposal_id, '12345678-1234-1234-1234-123456789abc');
    assert.match(result.data.next_step, /explicitly apply/);
    assert.equal(validated.owner, 'a'.repeat(64));
    assert.equal(validated.group, 'default');
  } finally {
    validator.close();
  }
  process.stdout.write('chat SCA proposal requires admin and saves only a reviewed draft: ok\n');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
