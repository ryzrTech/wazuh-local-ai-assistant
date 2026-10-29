const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

process.env.ASSISTANT_POLICY_TOKEN = 'v'.repeat(32);
process.env.ASSISTANT_POLICY_APPLY_TOKEN = 'a'.repeat(32);
const originalLoad = Module._load;
Module._load = function (name, parent, isMain) {
  if (name === '@osd/config-schema') return { schema: { object: () => ({}), string: () => ({}), number: () => ({}), boolean: () => ({}), maybe: () => ({}) } };
  return originalLoad(name, parent, isMain);
};
const { plugin } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function listen(port, handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  return server;
}

async function main() {
  const id = '12345678-1234-1234-1234-123456789abc';
  let applied = 0;
  const validator = await listen(8766, async (request, response) => {
    assert.equal(request.headers['x-policy-token'], 'v'.repeat(32));
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const payload = JSON.parse(Buffer.concat(chunks).toString());
    const body = request.url === '/proposal' ? { id, agent_id: '001', group_name: 'default', owner: payload.owner } : { proposals: [] };
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(body));
  });
  const executor = await listen(8768, async (request, response) => {
    assert.equal(request.headers['x-policy-apply-token'], 'a'.repeat(32));
    if (request.url === '/apply') applied++;
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ status: 'applied' }));
  });
  try {
    const routes = new Map();
    const router = { get: (route, handler) => routes.set(`GET ${route.path}`, handler),
      post: (route, handler) => routes.set(`POST ${route.path}`, handler),
      delete: (route, handler) => routes.set(`DELETE ${route.path}`, handler) };
    plugin({}).setup({ http: { createRouter: () => router } });
    const handler = routes.get('POST /api/wazuh_local_ai/policies/agent-sca/proposals/{id}/apply');
    let roles = ['viewer'];
    let groups = ['default'];
    const context = {
      core: { opensearch: { client: { asCurrentUser: { transport: { request: async () => ({ body: { user_name: 'operator', roles } }) } } } } },
      wazuh_core: {
        manageHosts: { get: async () => [{ id: 'host' }], isEnabledAuthWithRunAs: () => true },
        api: { client: { asCurrentUser: { authenticate: async () => 'token' } } },
        serverAPIClient: { _request: async () => ({ data: { data: { affected_items: [{ id: '001', group: groups }] } } }) },
      },
    };
    const response = { custom: (value) => value, badRequest: () => ({ statusCode: 400 }), unauthorized: () => ({ statusCode: 401 }),
      customError: (value) => value, notFound: () => ({ statusCode: 404 }) };
    const request = { params: { id }, body: {} };
    assert.equal((await handler(context, request, response)).statusCode, 403);
    assert.equal(applied, 0);
    roles = ['all_access']; groups = ['other'];
    assert.equal((await handler(context, request, response)).statusCode, 409);
    assert.equal(applied, 0);
    groups = ['default'];
    assert.equal((await handler(context, request, response)).statusCode, 200);
    assert.equal(applied, 1);
    process.stdout.write('policy apply route admin and group checks: ok\n');
  } finally {
    validator.close(); executor.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
