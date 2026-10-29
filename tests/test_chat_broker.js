const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

process.env.ASSISTANT_PROXY_TOKEN = 'x'.repeat(32);
const originalLoad = Module._load;
Module._load = function (name, parent, isMain) {
  if (name === '@osd/config-schema') return { schema: { object: () => ({}), string: () => ({}), number: () => ({}), boolean: () => ({}), maybe: () => ({}) } };
  return originalLoad(name, parent, isMain);
};
const { plugin } = require('../dashboard-plugin/native/server/index.js');
Module._load = originalLoad;

async function main() {
  let modelCalls = 0;
  let searched = false;
  let audited = false;
  let saved = false;
  let savedConcept = false;
  let toolResultSeen = false;
  const backend = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const payload = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    let result;
    if (request.url.endsWith('/turn')) result = { messages: [{ role: 'system', content: 'Use read tools' }, { role: 'user', content: payload.content }] };
    else if (request.url === '/api/model/complete-stream') {
      modelCalls++;
      if (payload.messages.some((item) => item.role === 'user' && item.content === 'Explain concept')) {
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write('event: delta\ndata: {"text":"Concept "}\n\n');
        response.write('event: delta\ndata: {"text":"explained."}\n\n');
        response.write('event: turn\ndata: {"content":"Concept explained.","tool_calls":[]}\n\n');
        response.end('event: done\ndata: {}\n\n');
        return;
      }
      response.writeHead(200, { 'Content-Type': 'text/event-stream' });
      response.write('event: delta\ndata: {"text":"Searching…"}\n\n');
      response.write('event: reset\ndata: {}\n\n');
      response.write('event: turn\ndata: {"content":"Searching…","tool_calls":[{"id":"call_1","type":"function","function":{"name":"search_alerts","arguments":"{\\"hours\\":24}"}}]}\n\n');
      response.end('event: done\ndata: {}\n\n');
      return;
    } else if (request.url === '/api/model/stream') {
      toolResultSeen = payload.messages.some((item) => item.role === 'tool' && item.content.includes('wazuh-alerts-example/abc'));
      response.writeHead(200, { 'Content-Type': 'text/event-stream' });
      response.write('event: delta\ndata: {"text":"One alert found "}\n\n');
      setTimeout(() => { response.write('event: delta\ndata: {"text":"[wazuh-alerts-example/abc]."}\n\n'); response.end('event: done\ndata: {}\n\n'); }, 10);
      return;
    } else if (request.url.endsWith('/tool-audit')) { audited = payload.name === 'search_alerts' && payload.count === 1; result = { saved: true }; }
    else if (request.url.endsWith('/assistant')) { saved ||= payload.content.includes('One alert found'); savedConcept ||= payload.content === 'Concept explained.'; result = { saved: true }; }
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
    assert.match(stream, /event: reset/);
    assert.match(stream, /event: done/);
    assert.match(stream, /One alert found/);
    assert.equal((stream.match(/event: delta/g) || []).length, 3);
    assert.equal(modelCalls, 1);
    assert.equal(searched && audited && saved && toolResultSeen, true);
    const concept = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Explain concept' } }, response);
    const conceptOutput = [];
    for await (const chunk of concept.body) conceptOutput.push(chunk.toString());
    const conceptStream = conceptOutput.join('');
    assert.equal((conceptStream.match(/event: delta/g) || []).length, 2);
    assert.doesNotMatch(conceptStream, /event: reset/);
    assert.match(conceptStream, /event: done/);
    assert.equal(savedConcept, true);
    process.stdout.write('chat broker tool round-trip, audit, and persistence: ok\n');
  } finally {
    backend.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
