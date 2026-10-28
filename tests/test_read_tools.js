const assert = require('node:assert/strict');
const path = require('node:path');
const esbuild = require(process.env.ESBUILD_PATH || 'esbuild');

const compiled = esbuild.buildSync({
  entryPoints: [path.join(__dirname, '..', 'dashboard-plugin/native/server/read_tools.ts')],
  bundle: true, platform: 'node', format: 'cjs', write: false,
}).outputFiles[0].text;
const moduleRef = { exports: {} };
new Function('module', 'exports', 'require', compiled)(moduleRef, moduleRef.exports, require);
const { executeReadTool, capabilities } = moduleRef.exports;

async function main() {
  let searched;
  const context = { core: { opensearch: { client: { asCurrentUser: { transport: {
    request: async (request) => {
      searched = request;
      return { body: { hits: { hits: [{ _index: 'wazuh-alerts-example', _id: 'abc',
        _source: { timestamp: '2026-01-01T00:00:00Z', rule: { id: '100100', level: 12 }, full_log: 'test' } }] } } };
    },
  } } } } } };
  const managerRead = async (_context, route) => route === '/agents' ? [{ id: '001', name: 'demo', group: ['default'] }] : [];

  assert.equal(capabilities(false).policy_apply, false);
  const available = await executeReadTool(context, 'get_capabilities', '{}', false, managerRead);
  assert.equal(available.data.read_tools.length, 4);
  const alerts = await executeReadTool(context, 'search_alerts', '{"hours":24,"rule_id":"100100"}', false, managerRead);
  assert.equal(alerts.count, 1);
  assert.equal(alerts.data.records[0].source_ref, 'wazuh-alerts-example/abc');
  assert.equal(searched.path, '/wazuh-alerts-*/_search');
  assert.equal(searched.body.size, 10);
  assert.equal(searched.body.query.bool.filter[2].term['rule.id'], '100100');
  await executeReadTool(context, 'search_raw_events', '{"hours":720}', false, managerRead);
  assert.equal(searched.path, '/wazuh-archives-*/_search');
  const agent = await executeReadTool(context, 'get_agent', '{"agent_id":"001"}', false, managerRead);
  assert.equal(agent.data.source_ref, 'agent:001');
  await assert.rejects(() => executeReadTool(context, 'search_alerts', '{"hours":721}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'search_alerts', '{"hours":24,"index":"*"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_agent', '{"agent_id":"../etc"}', false, managerRead));
  const denied = { core: { opensearch: { client: { asCurrentUser: { transport: { request: async () => { throw Object.assign(new Error('denied'), { statusCode: 403 }); } } } } } } };
  await assert.rejects(() => executeReadTool(denied, 'search_alerts', '{"hours":24}', false, managerRead), { statusCode: 403 });
  process.stdout.write('read tool bounds, sources, and permission propagation: ok\n');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
