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
  let savedUpdates = false;
  let savedConcept = false;
  let savedConceptThinking = false;
  let savedMalware = '';
  let savedXml = '';
  let savedMalformed = '';
  const malwareSearches = [];
  let toolResultSeen = false;
  const backend = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const payload = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    let result;
    if (request.url.endsWith('/turn')) result = { messages: [{ role: 'system', content: 'Use read tools' }, { role: 'user', content: payload.content }] };
    else if (request.url === '/api/model/complete-stream') {
      modelCalls++;
      const textProbe = payload.messages.find((item) => item.role === 'user' && ['Malformed probe', 'Text write probe'].includes(item.content))?.content;
      if (textProbe) {
        const content = textProbe === 'Malformed probe' ? 'Checking <tool_call><function=search_alerts>' :
          '<tool_call><function=propose_wazuh_action></function></tool_call>';
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write(`event: delta\ndata: ${JSON.stringify({ text: content })}\n\n`);
        response.write(`event: turn\ndata: ${JSON.stringify({ content, tool_calls: [] })}\n\n`);
        response.end('event: done\ndata: {}\n\n'); return;
      }
      if (payload.messages.some((item) => item.role === 'user' && item.content === 'XML probe')) {
        const prior = payload.messages.filter((item) => item.role === 'tool').length;
        const content = prior ? 'One alert found after the recovered call.' :
          'I will check alerts. <tool_call> <function=search_alerts> <parameter=hours> 24 </parameter> </function> </tool_call>';
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write(`event: delta\ndata: ${JSON.stringify({ text: content.slice(0, 24) })}\n\n`);
        response.write(`event: delta\ndata: ${JSON.stringify({ text: content.slice(24) })}\n\n`);
        response.write(`event: turn\ndata: ${JSON.stringify({ content, tool_calls: [] })}\n\n`);
        response.end('event: done\ndata: {}\n\n'); return;
      }
      if (payload.messages.some((item) => item.role === 'user' && item.content === 'Malware probe')) {
        const prior = payload.messages.filter((item) => item.role === 'tool').length;
        const terms = prior >= 5 ? [] : prior ? ['ransomware', 'trojan', 'virus', 'malicious'] : ['malware'];
        const tool_calls = terms.map((term, index) => ({ id: `malware_${index}`, type: 'function', function: {
          name: 'search_alerts', arguments: JSON.stringify({ hours: 168, text: term }),
        } }));
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write('event: reset\ndata: {}\n\n');
        response.write(`event: turn\ndata: ${JSON.stringify({ content: '', tool_calls })}\n\n`);
        response.end('event: done\ndata: {}\n\n');
        return;
      }
      if (payload.messages.some((item) => item.role === 'user' && item.content === 'Explain concept')) {
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write('event: thinking\ndata: {"text":"Check the concept first. "}\n\n');
        response.write('event: thinking\ndata: {"text":"Then explain."}\n\n');
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
      if (payload.messages.some((item) => item.role === 'user' && ['Malformed probe', 'Text write probe'].includes(item.content))) {
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write('event: delta\ndata: {"text":"I could not finish the investigation. Please retry."}\n\n');
        response.end('event: done\ndata: {}\n\n'); return;
      }
      if (payload.messages.some((item) => item.role === 'user' && item.content === 'Malware probe')) {
        response.writeHead(200, { 'Content-Type': 'text/event-stream' });
        response.write('event: delta\ndata: {"text":"I will broaden the search. "}\n\n');
        response.write('event: delta\ndata: {"text":"<tool_"}\n\n');
        response.write('event: delta\ndata: {"text":"call><function=search_alerts>"}\n\n');
        response.end('event: done\ndata: {}\n\n');
        return;
      }
      toolResultSeen = payload.messages.some((item) => item.role === 'tool' && item.content.includes('wazuh-alerts-example/abc'));
      response.writeHead(200, { 'Content-Type': 'text/event-stream' });
      response.write('event: delta\ndata: {"text":"One alert found "}\n\n');
      setTimeout(() => { response.write('event: delta\ndata: {"text":"[wazuh-alerts-example/abc]."}\n\n'); response.end('event: done\ndata: {}\n\n'); }, 10);
      return;
    } else if (request.url.endsWith('/tool-audit')) { audited = payload.name === 'search_alerts' && payload.count === 1; result = { saved: true }; }
    else if (request.url.endsWith('/assistant')) { if (payload.content.includes('One alert found') && !payload.content.includes('recovered call')) assert.equal(payload.updates, 'Searching…'); saved ||= payload.content.includes('One alert found'); savedUpdates ||= payload.content.includes('One alert found') && payload.updates === 'Searching…'; savedConcept ||= payload.content === 'Concept explained.'; savedConceptThinking ||= payload.content === 'Concept explained.' && payload.thinking === 'Check the concept first. Then explain.'; if (payload.content.includes('Completed Wazuh tool calls')) savedMalware = payload.content; if (payload.content.includes('recovered call')) { assert.equal(payload.updates, 'I will check alerts.'); savedXml = payload.content; } if (payload.content.includes('could not finish')) savedMalformed = payload.content; result = { saved: true }; }
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
        if (query.body.query.bool.must.length) {
          malwareSearches.push(query.body.query.bool.must[0].multi_match.query);
          return { body: { hits: { hits: [] } } };
        }
        return { body: { hits: { hits: [{ _index: 'wazuh-alerts-example', _id: 'abc',
          _source: { timestamp: '2026-01-01T00:00:00Z', rule: { id: '100100', level: 12 } } }] } } };
      }
      throw new Error('unexpected search');
    } } } } } } };
    const response = { custom: (value) => value, badRequest: () => ({ statusCode: 400 }), unauthorized: () => ({ statusCode: 401 }), customError: (value) => value };
    const result = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Show alerts' } }, response);
    assert.equal(result.statusCode, 200);
    assert.equal(result.headers['Content-Encoding'], 'identity');
    const output = [];
    for await (const chunk of result.body) output.push(chunk.toString());
    const stream = output.join('');
    assert.match(stream, /event: tool/);
    assert.match(stream, /event: reset/);
    assert.match(stream, /event: progress\ndata: \{"text":"Searching…"\}/);
    assert.match(stream, /event: done/);
    assert.match(stream, /One alert found/);
    assert.equal((stream.slice(stream.lastIndexOf('event: reset')).match(/event: delta/g) || []).length, 2);
    assert.equal(modelCalls, 4);
    assert.deepEqual({ searched, audited, saved, savedUpdates, toolResultSeen },
      { searched: true, audited: true, saved: true, savedUpdates: true, toolResultSeen: true });
    const concept = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Explain concept' } }, response);
    const conceptOutput = [];
    for await (const chunk of concept.body) conceptOutput.push(chunk.toString());
    const conceptStream = conceptOutput.join('');
    assert.equal((conceptStream.match(/event: delta/g) || []).length, 2);
    assert.equal((conceptStream.match(/event: thinking/g) || []).length, 2);
    assert.doesNotMatch(conceptStream, /event: reset/);
    assert.match(conceptStream, /event: done/);
    assert.equal(savedConcept && savedConceptThinking, true);
    const malware = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Malware probe' } }, response);
    const malwareOutput = [];
    for await (const chunk of malware.body) malwareOutput.push(chunk.toString());
    const malwareStream = malwareOutput.join('');
    assert.deepEqual(malwareSearches, ['malware', 'ransomware', 'trojan', 'virus', 'malicious']);
    assert.match(malwareStream, /event: reset/);
    assert.doesNotMatch(malwareStream, /<tool_call>|<function=/);
    assert.match(savedMalware, /Completed Wazuh tool calls/);
    assert.doesNotMatch(savedMalware, /<tool_call>|<function=/);
    const xml = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'XML probe' } }, response);
    const xmlOutput = [];
    for await (const chunk of xml.body) xmlOutput.push(chunk.toString());
    const xmlStream = xmlOutput.join('');
    assert.match(xmlStream, /event: tool\ndata: \{"name":"search_alerts","status":"ok","count":1\}/);
    assert.match(xmlStream, /recovered call/);
    assert.doesNotMatch(xmlStream, /<tool_call>|<function=/);
    assert.equal(savedXml, 'One alert found after the recovered call.');
    const malformed = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Malformed probe' } }, response);
    const malformedOutput = [];
    for await (const chunk of malformed.body) malformedOutput.push(chunk.toString());
    assert.doesNotMatch(malformedOutput.join(''), /<tool_call>|<function=/);
    assert.equal(savedMalformed, 'I could not finish the investigation. Please retry.');
    const denied = await handler(context, { params: { id: '12345678-1234-1234-1234-123456789abc' }, body: { content: 'Text write probe' } }, response);
    const deniedOutput = [];
    for await (const chunk of denied.body) deniedOutput.push(chunk.toString());
    assert.doesNotMatch(deniedOutput.join(''), /event: tool|<tool_call>|<function=/);
    process.stdout.write('chat broker tool round-trip, audit, and persistence: ok\n');
  } finally {
    backend.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
