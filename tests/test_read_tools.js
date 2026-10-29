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
      if (request.path === '/wazuh-states-vulnerabilities-*/_search') return { body: { hits: { hits: [
        { _index: 'wazuh-states-vulnerabilities-example', _id: 'cve-1', _source: {
          agent: { id: '001' }, package: { name: 'example', version: '1.0' },
          vulnerability: { id: 'CVE-2026-0001', severity: 'High', score: { base: 8.1 }, detected_at: '2026-01-01T00:00:00Z' },
        } },
      ] } } };
      return { body: { hits: { hits: [{ _index: 'wazuh-alerts-example', _id: 'abc',
        _source: { timestamp: '2026-01-01T00:00:00Z', rule: { id: '100100', level: 12 }, full_log: 'test' } }] } } };
    },
  } } } } } };
  let managerCall;
  const managerRead = async (_context, route, params) => {
    managerCall = { route, params };
    if (route === '/agents') return [{ id: '001', name: 'demo', group: ['default'] }];
    if (route.endsWith('/packages')) return [{ name: 'example', version: '1.0', scan: { time: '2026-01-01T00:00:00Z' } }];
    if (route.endsWith('/processes')) return [{ pid: '42', name: 'example', euser: 'user' }];
    if (route.endsWith('/ports')) return [{ local: { ip: '127.0.0.1', port: 55555 }, protocol: 'tcp', process: 'example' }];
    if (route === '/rootcheck/001') return [{ status: 'outstanding', title: 'Port finding', password: 'must-not-leak' }];
    if (route === '/syscheck/001') return [{ file: '/etc/example', event: 'modified' }];
    if (route === '/rules') return [{ id: '510', level: 7, description: 'Rootcheck event' }];
    if (route === '/manager/status') return [{ wazuh_analysisd: 'running' }];
    if (route === '/sca/001/checks/policy_a') return [{ id: 7, title: 'Sample check', result: 'failed' }];
    if (route === '/agents/001/config/syscheck/rootcheck') return [{ check_ports: 'yes' }];
    return [];
  };

  assert.equal(capabilities(false).chat_policy_apply, false);
  assert.equal(capabilities(true).signed_in_user_can_review_agent_sca_changes, true);
  assert.equal(capabilities(true).exclusion_rule_apply, false);
  assert.match(capabilities(true).note, /model tools/);
  const available = await executeReadTool(context, 'get_capabilities', '{}', false, managerRead);
  assert.equal(available.data.read_tools.length, 9);
  assert.ok(available.data.wazuh_data_sources.includes('rootcheck'));
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
  const packages = await executeReadTool(context, 'get_software_inventory', '{"agent_id":"001","search":"example"}', false, managerRead);
  assert.equal(managerCall.route, '/syscollector/001/packages');
  assert.equal(managerCall.params.search, 'example');
  assert.equal(packages.data.records[0].name, 'example');
  const processes = await executeReadTool(context, 'get_processes', '{"agent_id":"001","pid":42}', false, managerRead);
  assert.equal(managerCall.route, '/syscollector/001/processes');
  assert.equal(managerCall.params.pid, '42');
  assert.equal(processes.data.records[0].pid, '42');
  const ports = await executeReadTool(context, 'get_ports', '{"agent_id":"001","local_port":55555}', false, managerRead);
  assert.equal(managerCall.route, '/syscollector/001/ports');
  assert.equal(managerCall.params.q, 'local.port=55555');
  assert.equal(ports.data.records[0].local_port, 55555);
  const vulnerabilities = await executeReadTool(context, 'get_vulnerabilities', '{"agent_id":"001","min_score":7}', false, managerRead);
  assert.equal(searched.path, '/wazuh-states-vulnerabilities-*/_search');
  assert.equal(searched.body.query.bool.filter[0].term['agent.id'], '001');
  assert.equal(vulnerabilities.data.records[0].cve, 'CVE-2026-0001');
  const rootcheck = await executeReadTool(context, 'get_wazuh_data', '{"source":"rootcheck","agent_id":"001"}', false, managerRead);
  assert.equal(managerCall.route, '/rootcheck/001');
  assert.equal(rootcheck.data.records[0].title, 'Port finding');
  assert.equal(rootcheck.data.records[0].password, undefined);
  await executeReadTool(context, 'get_wazuh_data', '{"source":"fim","agent_id":"001"}', false, managerRead);
  assert.equal(managerCall.route, '/syscheck/001');
  await executeReadTool(context, 'get_wazuh_data', '{"source":"rules","rule_id":"510"}', false, managerRead);
  assert.equal(managerCall.params.rule_ids, '510');
  await executeReadTool(context, 'get_wazuh_data', '{"source":"manager_status"}', false, managerRead);
  assert.equal(managerCall.route, '/manager/status');
  await executeReadTool(context, 'get_wazuh_data', '{"source":"sca_checks","agent_id":"001","policy_id":"policy_a"}', false, managerRead);
  assert.equal(managerCall.route, '/sca/001/checks/policy_a');
  await executeReadTool(context, 'get_wazuh_data', '{"source":"agent_rootcheck_config","agent_id":"001"}', false, managerRead);
  assert.equal(managerCall.route, '/agents/001/config/syscheck/rootcheck');
  await assert.rejects(() => executeReadTool(context, 'search_alerts', '{"hours":721}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'search_alerts', '{"hours":24,"index":"*"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_agent', '{"agent_id":"../etc"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_ports', '{"agent_id":"001","local_port":65536}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_vulnerabilities', '{"agent_id":"001","offset":5001}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_wazuh_data', '{"source":"rootcheck"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_wazuh_data', '{"source":"../secrets"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_wazuh_data', '{"source":"rules","agent_id":"001"}', false, managerRead));
  await assert.rejects(() => executeReadTool(context, 'get_wazuh_data', '{"source":"sca_checks","agent_id":"001","policy_id":"../secret"}', false, managerRead));
  const denied = { core: { opensearch: { client: { asCurrentUser: { transport: { request: async () => { throw Object.assign(new Error('denied'), { statusCode: 403 }); } } } } } } };
  await assert.rejects(() => executeReadTool(denied, 'search_alerts', '{"hours":24}', false, managerRead), { statusCode: 403 });
  await assert.rejects(() => executeReadTool(context, 'get_software_inventory', '{"agent_id":"001"}', false,
    async () => { throw Object.assign(new Error('denied'), { statusCode: 403 }); }), { statusCode: 403 });
  process.stdout.write('read tool bounds, sources, and permission propagation: ok\n');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
