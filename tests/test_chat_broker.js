const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

process.env.ASSISTANT_PROXY_TOKEN = 'x'.repeat(32);
const originalLoad = Module._load;
Module._load = function (name, parent, isMain) {
  if (name === '@osd/config-schema') return { schema: { object: () => ({}), string: () => ({}), number: () => ({}), maybe: () => ({}) } };
  return originalLoad(name, parent, isMain);
};
const { plugin } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function main() {
  let modelCalls = 0;
  let searched = false;
  let audited = false;
  let saved = false;
  let toolResultSeen = false;
  const backend = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const payload = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    let result;
    if (request.url.endsWith('/turn')) result = { messages: [{ role: 'system', content: 'Use read tools' }, { role: 'user', content: payload.content }] };
    else if (request.url === '/api/model/complete') {
      modelCalls++;
      if (modelCalls === 1) result = { content: '', tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'search_alerts', arguments: '{"hours":24}' } }] };
      else {
        toolResultSeen = payload.messages.some((item) => item.role === 'tool' && item.content.includes('wazuh-alerts-example/abc'));
        result = { content: 'One alert found [wazuh-alerts-example/abc].', tool_calls: [] };
      }
    } else if (request.url.endsWith('/tool-audit')) { audited = payload.name === 'search_alerts' && payload.count === 1; result = { saved: true }; }
    else if (request.url.endsWith('/assistant')) { saved = payload.content.includes('One alert found'); result = { saved: true }; }
    else { response.writeHead(404); response.end('{}'); return; }
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(result));
  });
  await new Promise((resolve) => backend.listen(8765, '127.0.0.1', resolve));
  try {
    const routes = new Map();
    const router = { get: (route, handler) => routes.set(`GET ${route.path}`, handler),
      post: (route, handler) => routes.set(`POST ${route.path}`, handler),
      delete: (route, handler) => routes.set(`DELETE ${route.path}`, handler) };
    plugin({}).setup({ http: { createRouter: () => router } });
    const handler = routes.get('POST /api/wazuh_local_ai/sessions/{id}/messages');
    const context = { core: { opensearch: { client: { asCurrentUser: { transport: { request: async (query) => {
      if (query.path === '/_plugins/_security/authinfo') return { body: { user_name: 'test-user', roles: ['all_access'] } };
      if (query.path === '/wazuh-alerts-*/_search') {
        searched = query.body.size === 10;
        return { body: { hits: { hits: [{ _index: 'wazuh-alerts-example', _id: 'abc',
          _source: { timestamp: '2026-01-01T00:00:00Z', rule: { id: '100100', level: 12 } } }] } } };
      }
      throw new Error('unexpected search');
    } } } } } } };
    const response = { custom: (value) => value, badRequest: () => ({ statusCode: 400 }), unauthorized: () => ({ statusCode: 401 }), customError: (value) => value };
    const result = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Show alerts' } }, response);
    assert.equal(result.statusCode, 200);
    const output = [];
    for await (const chunk of result.body) output.push(chunk.toString());
    const stream = output.join('');
    assert.match(stream, /event: tool/);
    assert.match(stream, /event: done/);
    assert.match(stream, /One alert found/);
    assert.equal(modelCalls, 2);
    assert.equal(searched && audited && saved && toolResultSeen, true);
    process.stdout.write('chat broker tool round-trip, audit, and persistence: ok\n');
  } finally {
    backend.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
