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
const { plugin } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function main() {
  const id = '12345678-1234-1234-1234-123456789abc';
  let action = { id, status: 'pending', action: 'restart_agent', agent_id: '001', target_ip: '',
    evidence_ref: '', reason: 'Restart this stalled agent' };
  let calls = [];
  const backend = http.createServer(async (request, response) => {
    assert.equal(request.headers['x-assistant-admin-token'], process.env.ASSISTANT_ADMIN_TOKEN);
    if (request.url === '/api/actions/proposals' && request.method === 'GET') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ proposals: [action] })); return;
    }
    for await (const _ of request) { /* drain */ }
    calls.push(request.url);
    if (request.url.endsWith('/claim') && action.status === 'pending') action = { ...action, status: 'dispatching' };
    else if (request.url.endsWith('/sent') && action.status === 'dispatching') action = { ...action, status: 'sent', result: 'accepted' };
    else if (request.url.endsWith('/deny') && action.status === 'pending') action = { ...action, status: 'denied' };
    else { response.writeHead(409); response.end('{}'); return; }
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(action));
  });
  await new Promise((resolve) => backend.listen(8765, '127.0.0.1', resolve));
  try {
    const routes = new Map();
    const router = { get: (route, handler) => routes.set(`GET ${route.path}`, handler),
      post: (route, handler) => routes.set(`POST ${route.path}`, handler),
      delete: (route, handler) => routes.set(`DELETE ${route.path}`, handler) };
    plugin({}).setup({ http: { createRouter: () => router } });
    let admin = true;
    let agentOs = 'Ubuntu';
    let alertIp = '203.0.113.5';
    const writes = [];
    const context = { core: { opensearch: { client: { asCurrentUser: { transport: { request: async ({ path }) => ({ body: path.startsWith('/wazuh-alerts-') ? {
      _source: { agent: { id: '001' }, data: { srcip: alertIp } },
    } : { user_name: 'analyst', roles: admin ? ['all_access'] : [] } }) } } } } }, wazuh_core: {
      manageHosts: { get: async () => [{ id: 'host' }], isEnabledAuthWithRunAs: () => true },
      api: { client: { asCurrentUser: { authenticate: async () => 'scoped-token' } } },
      serverAPIClient: { _request: async (method, path, data) => {
        if (method === 'GET' && path === '/agents') return { data: { data: { affected_items: [{ id: '001', status: 'active', os: { name: agentOs } }] } } };
        writes.push({ method, path, data });
        return { data: { error: 0, data: { affected_items: ['001'], total_failed_items: 0 } } };
      } },
    } };
    const response = { custom: (value) => value, customError: (value) => value,
      badRequest: () => ({ statusCode: 400 }), unauthorized: () => ({ statusCode: 401 }) };
    const approve = routes.get('POST /api/wazuh_local_ai/actions/proposals/{id}/approve');
    admin = false;
    assert.equal((await approve(context, { params: { id }, body: {} }, response)).statusCode, 403);
    assert.equal(writes.length, 0);
    admin = true;
    assert.equal((await approve(context, { params: { id }, body: {} }, response)).statusCode, 200);
    assert.equal(writes[0].path, '/agents/001/restart');
    assert.deepEqual(calls.slice(-2), [`/api/actions/proposals/${id}/claim`, `/api/actions/proposals/${id}/sent`]);
    action = { ...action, status: 'pending', action: 'block_ip', target_ip: '203.0.113.5', evidence_ref: 'wazuh-alerts-example/1' };
    agentOs = 'macOS';
    assert.equal((await approve(context, { params: { id }, body: {} }, response)).statusCode, 409);
    assert.equal(writes.length, 1);
    agentOs = 'Ubuntu';
    alertIp = '203.0.113.6';
    assert.equal((await approve(context, { params: { id }, body: {} }, response)).statusCode, 409);
    assert.equal(writes.length, 1);
    alertIp = '203.0.113.5';
    assert.equal((await approve(context, { params: { id }, body: {} }, response)).statusCode, 200);
    assert.equal(writes[1].path, '/active-response');
    assert.equal(writes[1].data.params.agents_list, '001');
    assert.equal(writes[1].data.body.alert.data.srcip, '203.0.113.5');
    process.stdout.write('action routes require admin, one agent, approval, and OS check: ok\n');
  } finally { backend.close(); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
