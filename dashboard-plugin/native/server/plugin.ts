import { createHash } from 'crypto';
import { IncomingMessage, request as httpRequest } from 'http';
import { PassThrough } from 'stream';
import { schema } from '@osd/config-schema';
import { CoreSetup, Plugin, PluginInitializerContext } from 'opensearch_dashboards/server';
import { capabilities, executeReadTool } from './read_tools';

const PREFIX = '/api/wazuh_local_ai';
const SESSION_ID = /^[a-f0-9-]{36}$/;
const AGENT_ID = /^\d{1,6}$/;
const GROUP = /^[A-Za-z0-9_.-]{1,64}$/;
const INDEX = /^wazuh-(alerts|archives)-[a-zA-Z0-9._-]+$/;

type RouteResponse = {
  status: number;
  body: IncomingMessage;
};

function proxy(method: 'GET' | 'POST' | 'DELETE', path: string, owner: string, payload?: unknown, admin = false): Promise<RouteResponse> {
  const token = process.env.ASSISTANT_PROXY_TOKEN || '';
  if (token.length < 32) return Promise.reject(new Error('proxy token missing'));
  const adminToken = process.env.ASSISTANT_ADMIN_TOKEN || '';
  if (admin && adminToken.length < 32) return Promise.reject(new Error('admin token missing'));
  const body = payload === undefined ? undefined : JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const upstream = httpRequest({
      hostname: '127.0.0.1', port: 8765, method, path,
      timeout: 90000,
      headers: {
        'X-Assistant-Token': token,
        'X-Assistant-User': owner,
        ...(admin ? { 'X-Assistant-Admin-Token': adminToken } : {}),
        ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    }, (response) => resolve({ status: response.statusCode || 502, body: response }));
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', reject);
    upstream.end(body);
  });
}

async function currentIdentity(context: any) {
  const auth = await context.core.opensearch.client.asCurrentUser.transport.request({
    method: 'GET', path: '/_plugins/_security/authinfo',
  });
  const info = auth.body || auth;
  if (typeof info.user_name !== 'string' || !info.user_name) return null;
  const tenant = typeof info.user_requested_tenant === 'string' ? info.user_requested_tenant : '';
  return {
    owner: createHash('sha256').update(info.user_name + '\0' + tenant).digest('hex'),
    roles: Array.isArray(info.roles) ? info.roles : [],
  };
}

async function managerRead(context: any, path: string, params: Record<string, unknown> = {}) {
  const hosts = await context.wazuh_core.manageHosts.get(undefined, { excludePassword: true });
  const apiHostID = hosts[0]?.id;
  if (!apiHostID) throw new Error('No Wazuh API host configured');
  if (!context.wazuh_core.manageHosts.isEnabledAuthWithRunAs(apiHostID)) {
    throw new Error('Wazuh API run-as is required');
  }
  // Authenticate with the Dashboard request's user context. This avoids depending on
  // a preexisting wz-token cookie when the investigations app is opened directly.
  const token = await context.wazuh_core.api.client.asCurrentUser.authenticate(apiHostID);
  const result = await context.wazuh_core.serverAPIClient._request('GET', path, { params, timeout: 10000 }, { apiHostID, token });
  return result.data?.data?.affected_items || [];
}

function policyRequest(action: 'validator' | 'apply', path: string, payload: unknown): Promise<{ status: number; body: any }> {
  const token = action === 'validator' ? process.env.ASSISTANT_POLICY_TOKEN || '' : process.env.ASSISTANT_POLICY_APPLY_TOKEN || '';
  if (token.length < 32) return Promise.reject(new Error('policy token missing'));
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const upstream = httpRequest({
      hostname: '127.0.0.1', port: action === 'validator' ? 8766 : 8768, method: 'POST', path, timeout: 20000,
      headers: { [action === 'validator' ? 'X-Policy-Token' : 'X-Policy-Apply-Token']: token,
        'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (result) => {
      const chunks: Buffer[] = [];
      result.on('data', (chunk: Buffer) => chunks.push(chunk));
      result.on('end', () => {
        try { resolve({ status: result.statusCode || 502, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { reject(new Error('invalid policy service response')); }
      });
    });
    upstream.on('timeout', () => upstream.destroy(new Error('policy service timeout')));
    upstream.on('error', reject);
    upstream.end(body);
  });
}

function alertService(method: 'GET' | 'POST', path: string, payload?: unknown): Promise<{ status: number; body: any }> {
  const token = process.env.ASSISTANT_ALERT_TOKEN || '';
  if (token.length < 32) return Promise.reject(new Error('alert token missing'));
  const body = payload === undefined ? undefined : JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const upstream = httpRequest({
      hostname: '127.0.0.1', port: 8767, method, path, timeout: 15000,
      headers: {
        'X-Alert-Token': token,
        ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    }, (result) => {
      const chunks: Buffer[] = [];
      result.on('data', (chunk: Buffer) => chunks.push(chunk));
      result.on('end', () => {
        try { resolve({ status: result.statusCode || 502, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { reject(new Error('invalid alert service response')); }
      });
    });
    upstream.on('timeout', () => upstream.destroy(new Error('alert service timeout')));
    upstream.on('error', reject);
    upstream.end(body);
  });
}

function adminAllowed(identity: { roles: unknown[] }) {
  const allowed = new Set((process.env.ASSISTANT_ADMIN_ROLES || 'all_access').split(',').map((role) => role.trim()).filter(Boolean));
  return identity.roles.some((role: unknown) => typeof role === 'string' && allowed.has(role));
}

async function proxyJson(method: 'GET' | 'POST', path: string, owner: string, payload?: unknown): Promise<{ status: number; data: any }> {
  const upstream = await proxy(method, path, owner, payload);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of upstream.body) {
    size += chunk.length;
    if (size > 131072) { upstream.body.destroy(); throw new Error('Assistant response exceeded limit'); }
    chunks.push(chunk);
  }
  let data: any;
  try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new Error('Invalid assistant response'); }
  return { status: upstream.status, data };
}

function sendEvent(stream: PassThrough, event: string, data: unknown) {
  stream.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

async function readModelStream(owner: string, path: string, messages: any[], onEvent: (event: string, payload: any) => void) {
  const upstream = await proxy('POST', path, owner, { messages });
  if (upstream.status !== 200) { upstream.body.resume(); throw new Error('Model request failed'); }
  const decoder = new TextDecoder();
  let buffer = '';
  let completed = false;
  for await (const chunk of upstream.body) {
    buffer += decoder.decode(chunk, { stream: true }).replace(/\r/g, '');
    if (buffer.length > 65536) throw new Error('Invalid model stream');
    let boundary: number;
    while ((boundary = buffer.indexOf('\n\n')) >= 0) {
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const event = frame.match(/^event: (.+)$/m)?.[1];
      const data = frame.match(/^data: (.+)$/m)?.[1];
      if (!event || !data) continue;
      let payload: any;
      try { payload = JSON.parse(data); } catch { throw new Error('Invalid model stream'); }
      if (event === 'error') throw new Error('Model stream failed');
      if (event === 'done') completed = true;
      onEvent(event, payload);
    }
  }
  if (!completed) throw new Error('Model stream ended early');
}

async function streamModelTurn(owner: string, messages: any[], stream: PassThrough): Promise<any> {
  let turn: any;
  let contentSize = 0;
  await readModelStream(owner, '/api/model/complete-stream', messages, (event, payload) => {
    if (event === 'delta') {
      if (typeof payload.text !== 'string') throw new Error('Invalid model stream');
      contentSize += payload.text.length;
      if (contentSize > 16000) throw new Error('Model answer exceeded limit');
      sendEvent(stream, 'delta', { text: payload.text });
    }
    if (event === 'reset') sendEvent(stream, 'reset', {});
    if (event === 'turn') turn = payload;
  });
  if (!turn || typeof turn.content !== 'string' || !Array.isArray(turn.tool_calls)) throw new Error('Invalid model turn');
  return turn;
}

async function streamFinalAnswer(owner: string, messages: any[], stream: PassThrough): Promise<string> {
  let answer = '';
  await readModelStream(owner, '/api/model/stream', messages, (event, payload) => {
    if (event === 'delta') {
      if (typeof payload.text !== 'string') throw new Error('Invalid model stream');
      answer += payload.text;
      if (answer.length > 16000) throw new Error('Model answer exceeded limit');
      sendEvent(stream, 'delta', { text: payload.text });
    }
  });
  if (!answer.trim()) throw new Error('Empty model answer');
  return answer;
}

async function chatWithTools(context: any, owner: string, admin: boolean, sessionId: string, content: string, retry: boolean, stream: PassThrough) {
  const allowed = new Set(['get_capabilities', 'search_alerts', 'search_raw_events', 'get_agent', 'get_sca_results']);
  let stage = 'prepare';
  try {
    const prepared = await proxyJson('POST', `/api/sessions/${sessionId}/turn`, owner, { content, retry });
    if (prepared.status !== 200 || !Array.isArray(prepared.data.messages)) throw new Error('Could not prepare chat');
    const messages: any[] = prepared.data.messages;
    stage = 'model';
    const turn = await streamModelTurn(owner, messages, stream);
    if (!turn.tool_calls.length) {
      if (!turn.content.trim() || turn.content.length > 16000) throw new Error('Empty or oversized model answer');
      stage = 'save';
      const saved = await proxyJson('POST', `/api/sessions/${sessionId}/assistant`, owner, { content: turn.content });
      if (saved.status !== 200) throw new Error('Could not save answer');
      sendEvent(stream, 'done', { message: turn.content });
      stream.end();
      return;
    }
    if (turn.tool_calls.length > 4) throw new Error('Tool call limit reached');
    messages.push({ role: 'assistant', content: turn.content, tool_calls: turn.tool_calls });
    stage = 'tools';
    for (const call of turn.tool_calls) {
      const name = call?.function?.name;
      const id = call?.id;
      if (typeof name !== 'string' || !allowed.has(name) || typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) {
        throw new Error('Unsupported model tool call');
      }
      const started = Date.now();
      let status: 'ok' | 'denied' | 'error' = 'ok';
      let argumentsForAudit: Record<string, unknown> = {};
      let count = 0;
      let result: any;
      try {
        const executed = await executeReadTool(context, name, call.function.arguments, admin, managerRead);
        argumentsForAudit = executed.arguments;
        count = executed.count;
        result = executed.data;
        if (JSON.stringify(result).length > 12000) throw new Error('Tool result exceeded limit');
      } catch (error) {
        status = (error as any)?.statusCode === 401 || (error as any)?.statusCode === 403 ? 'denied' : 'error';
        result = { error: status === 'denied' ? 'Source permission denied' : 'Tool unavailable or invalid arguments' };
      }
      const audit = await proxyJson('POST', `/api/sessions/${sessionId}/tool-audit`, owner, {
        name, arguments: argumentsForAudit, status, count, duration_ms: Math.min(180000, Date.now() - started),
      });
      if (audit.status !== 200) throw new Error('Tool audit unavailable');
      sendEvent(stream, 'tool', { name, status, count });
      messages.push({ role: 'tool', tool_call_id: id, name, content: JSON.stringify(result) });
    }
    stage = 'stream';
    const answer = await streamFinalAnswer(owner, messages, stream);
    stage = 'save';
    const saved = await proxyJson('POST', `/api/sessions/${sessionId}/assistant`, owner, { content: answer });
    if (saved.status !== 200) throw new Error('Could not save answer');
    sendEvent(stream, 'done', {});
    stream.end();
  } catch (error) {
    console.warn('[wazuh-local-ai] chat failed', { stage, reason: error instanceof Error ? error.message : 'unknown' });
    sendEvent(stream, 'error', { error: 'Assistant request failed. Your message may have been saved; check the conversation before retrying.' });
    stream.end();
  }
}

function conciseSource(source: any) {
  return {
    timestamp: source.timestamp,
    agent: source.agent ? { id: source.agent.id, name: source.agent.name } : undefined,
    rule: source.rule ? { id: source.rule.id, level: source.rule.level, description: source.rule.description, groups: source.rule.groups } : undefined,
    location: source.location,
    decoder: source.decoder?.name,
    full_log: typeof source.full_log === 'string' ? source.full_log.slice(0, 1400) : undefined,
    data: source.data ? JSON.stringify(source.data).slice(0, 1400) : undefined,
  };
}

function agentGroups(agent: any): string[] {
  if (Array.isArray(agent.group)) return agent.group.filter((value: unknown) => typeof value === 'string');
  if (typeof agent.group === 'string') return agent.group.split(',').map((value: string) => value.trim()).filter(Boolean);
  return [];
}

export class LocalAiServerPlugin implements Plugin {
  constructor(_context: PluginInitializerContext) {}

  setup(core: CoreSetup) {
    const router = core.http.createRouter();
    const handle = (method: 'GET' | 'POST' | 'DELETE', routePath: string, pathFromRequest: (request: any) => string, adminOnly = false) =>
      async (context: any, request: any, response: any) => {
        try {
          // The indexer resolves identity from the current Dashboard request.
          const identity = await currentIdentity(context);
          if (!identity) return response.unauthorized();
          if (adminOnly) {
            if (!adminAllowed(identity)) {
              return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
            }
          }
          const upstream = await proxy(method, pathFromRequest(request), identity.owner, method === 'POST' ? request.body : undefined, adminOnly);
          return response.custom({
            statusCode: upstream.status,
            headers: {
              'Content-Type': routePath.endsWith('/messages') && method === 'POST'
                ? 'text/event-stream' : 'application/json',
              'Cache-Control': 'no-store',
              'X-Content-Type-Options': 'nosniff',
            },
            body: upstream.body,
          });
        } catch {
          return response.customError({ statusCode: 503, body: { message: 'Assistant unavailable' } });
        }
      };

    router.get({ path: PREFIX + '/models', validate: false }, handle('GET', '/models', () => '/api/models'));
    router.get({ path: PREFIX + '/capabilities', validate: false }, async (context: any, _request: any, response: any) => {
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        return response.ok({ body: capabilities(adminAllowed(identity)) });
      } catch { return response.customError({ statusCode: 503, body: { message: 'Capabilities unavailable' } }); }
    });
    router.get({ path: PREFIX + '/sessions', validate: false }, handle('GET', '/sessions', () => '/api/sessions'));
    router.post({ path: PREFIX + '/sessions', validate: { body: schema.object({}) } }, handle('POST', '/sessions', () => '/api/sessions'));
    router.delete({ path: PREFIX + '/sessions', validate: false }, handle('DELETE', '/sessions', () => '/api/sessions'));
    router.get({ path: PREFIX + '/settings', validate: false }, handle('GET', '/settings', () => '/api/settings'));
    router.post({ path: PREFIX + '/settings', validate: { body: schema.object({ retention_days: schema.number({ min: 0, max: 365 }) }) } },
      handle('POST', '/settings', () => '/api/settings'));
    router.get({ path: PREFIX + '/provider/config', validate: false }, handle('GET', '/provider/config', () => '/api/provider/config', true));

    const alertRoute = (method: 'GET' | 'POST', path: string) => async (context: any, request: any, response: any) => {
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        if (!adminAllowed(identity)) return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
        const result = await alertService(method, path, method === 'POST' ? request.body : undefined);
        return response.custom({ statusCode: result.status, headers: { 'Cache-Control': 'no-store' }, body: result.body });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Alert delivery service unavailable' } });
      }
    };
    router.get({ path: PREFIX + '/alerts/config', validate: false }, alertRoute('GET', '/config'));
    router.post({ path: PREFIX + '/alerts/config', validate: { body: schema.object({
      mode: schema.string(), min_level: schema.number({ min: 10, max: 15 }), url: schema.string({ maxLength: 2048 }),
    }) } }, alertRoute('POST', '/config'));
    router.post({ path: PREFIX + '/alerts/test', validate: { body: schema.object({}) } }, alertRoute('POST', '/test'));
    router.post({ path: PREFIX + '/provider/test', validate: { body: schema.object({
      url: schema.string({ minLength: 1, maxLength: 2048 }),
      key: schema.maybe(schema.string({ maxLength: 4096 })),
    }) } }, handle('POST', '/provider/test', () => '/api/provider/test', true));
    router.post({ path: PREFIX + '/provider/config', validate: { body: schema.object({
      url: schema.string({ minLength: 1, maxLength: 2048 }),
      key: schema.maybe(schema.string({ maxLength: 4096 })),
      model: schema.string({ minLength: 1, maxLength: 256 }),
    }) } }, handle('POST', '/provider/config', () => '/api/provider/config', true));
    router.delete({ path: PREFIX + '/sessions/{id}', validate: { params: schema.object({ id: schema.string() }) } },
      handle('DELETE', '/sessions/{id}', (request) => {
        if (!SESSION_ID.test(request.params.id)) throw new Error('invalid session');
        return `/api/sessions/${request.params.id}`;
      }));
    router.get({ path: PREFIX + '/sessions/{id}/messages', validate: { params: schema.object({ id: schema.string() }) } },
      handle('GET', '/messages', (request) => {
        if (!SESSION_ID.test(request.params.id)) throw new Error('invalid session');
        return `/api/sessions/${request.params.id}/messages`;
      }));
    router.post({ path: PREFIX + '/sessions/{id}/messages', validate: {
      params: schema.object({ id: schema.string() }),
      body: schema.object({ content: schema.string({ minLength: 1, maxLength: 4000 }), retry: schema.maybe(schema.boolean()) }),
    } }, async (context: any, request: any, response: any) => {
      if (!SESSION_ID.test(request.params.id) || !request.body.content.trim()) return response.badRequest();
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        const stream = new PassThrough();
        void chatWithTools(context, identity.owner, adminAllowed(identity), request.params.id, request.body.content, request.body.retry === true, stream);
        return response.custom({ statusCode: 200, headers: {
          'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store',
          'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff',
        }, body: stream });
      } catch { return response.customError({ statusCode: 503, body: { message: 'Assistant unavailable' } }); }
    });

    router.get({ path: PREFIX + '/investigations', validate: false },
      handle('GET', '/investigations', () => '/api/investigations'));
    router.get({ path: PREFIX + '/investigations/{id}', validate: { params: schema.object({ id: schema.string() }) } },
      handle('GET', '/investigations/{id}', (request) => {
        if (!SESSION_ID.test(request.params.id)) throw new Error('invalid investigation');
        return `/api/investigations/${request.params.id}`;
      }));

    router.post({ path: PREFIX + '/records/search', validate: { body: schema.object({
      source_type: schema.string(), hours: schema.number({ min: 1, max: 720 }),
      min_level: schema.number({ min: 0, max: 16 }),
      agent_id: schema.maybe(schema.string({ maxLength: 6 })),
    }) } }, async (context: any, request: any, response: any) => {
      if (!['alert', 'archive'].includes(request.body.source_type)) return response.badRequest();
      if (request.body.agent_id && !AGENT_ID.test(request.body.agent_id)) return response.badRequest();
      try {
        const index = request.body.source_type === 'alert' ? 'wazuh-alerts-*' : 'wazuh-archives-*';
        const filters: any[] = [{ range: { timestamp: { gte: `now-${request.body.hours}h`, lte: 'now' } } }];
        if (request.body.agent_id) filters.push({ term: { 'agent.id': request.body.agent_id } });
        if (request.body.source_type === 'alert') filters.push({ range: { 'rule.level': { gte: request.body.min_level } } });
        const result = await context.core.opensearch.client.asCurrentUser.transport.request({
          method: 'POST', path: `/${index}/_search`, body: {
            size: 40, track_total_hits: false, timeout: '5s',
            sort: [{ timestamp: { order: 'desc' } }],
            _source: ['timestamp', 'agent.id', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'location', 'full_log'],
            query: { bool: { filter: filters } },
          },
        });
        const data = result.body || result;
        return response.ok({ body: { records: (data.hits?.hits || []).map((hit: any) => ({
          id: hit._id, index: hit._index, source: conciseSource(hit._source || {}),
        })) } });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Wazuh event search unavailable or not permitted' } });
      }
    });

    router.get({ path: PREFIX + '/agents', validate: false }, async (context: any, _request: any, response: any) => {
      try {
        const agents = await managerRead(context, '/agents', { limit: 50 });
        return response.ok({ body: { agents: agents.map((agent: any) => ({
          id: agent.id, name: agent.name, status: agent.status, os: agent.os?.name,
          group_config_status: agent.group_config_status,
          groups: agentGroups(agent),
        })) } });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Wazuh agent data unavailable or not permitted' } });
      }
    });

    router.get({ path: PREFIX + '/agents/{id}', validate: { params: schema.object({ id: schema.string() }) } },
      async (context: any, request: any, response: any) => {
        if (!AGENT_ID.test(request.params.id)) return response.badRequest();
        try {
          const agents = await managerRead(context, '/agents', { agents_list: request.params.id, limit: 1 });
          if (!agents.length) return response.notFound();
          const agent = agents[0];
          return response.ok({ body: { agent: { id: agent.id, name: agent.name, status: agent.status,
            group_config_status: agent.group_config_status, groups: agentGroups(agent) } } });
        } catch { return response.customError({ statusCode: 503, body: { message: 'Agent status unavailable or not permitted' } }); }
      });

    router.get({ path: PREFIX + '/agents/{id}/sca', validate: { params: schema.object({ id: schema.string() }) } },
      async (context: any, request: any, response: any) => {
        if (!AGENT_ID.test(request.params.id)) return response.badRequest();
        try {
          const policies = await managerRead(context, `/sca/${request.params.id}`, { limit: 50 });
          return response.ok({ body: { policies: policies.map((item: any) => ({
            policy_id: item.policy_id, name: item.name, score: item.score,
            pass: item.pass, fail: item.fail, invalid: item.invalid,
            total_checks: item.total_checks, end_scan: item.end_scan,
          })) } });
        } catch {
          return response.customError({ statusCode: 503, body: { message: 'SCA results unavailable or not permitted' } });
        }
      });

    router.post({ path: PREFIX + '/policies/agent-sca/validate', validate: { body: schema.object({
      agent_id: schema.string({ minLength: 1, maxLength: 6 }),
      group: schema.string({ minLength: 1, maxLength: 64 }),
      settings: schema.object({
        enabled: schema.string(), scan_on_start: schema.string(),
        skip_nfs: schema.string(), interval: schema.string(),
      }),
    }) } }, async (context: any, request: any, response: any) => {
      const { agent_id, group, settings } = request.body;
      if (!AGENT_ID.test(agent_id) || !GROUP.test(group) || group === '.' || group === '..') return response.badRequest();
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        if (!adminAllowed(identity)) {
          return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
        }
        const agents = await managerRead(context, '/agents', { agents_list: agent_id, limit: 1 });
        if (!agents.length) return response.notFound();
        const groups = agentGroups(agents[0]);
        if (!groups.includes(group)) return response.badRequest();
        const checked = await policyRequest('validator', '/validate', { group, settings, agent_id, owner: identity.owner });
        return response.custom({ statusCode: checked.status, headers: { 'Cache-Control': 'no-store' }, body: checked.body });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Wazuh policy validation unavailable' } });
      }
    });

    const proposalRoute = (action: 'status' | 'apply' | 'rollback') => async (context: any, request: any, response: any) => {
      if (!SESSION_ID.test(request.params.id)) return response.badRequest();
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        if (!adminAllowed(identity)) return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
        const proposal = await policyRequest('validator', '/proposal', { proposal_id: request.params.id, owner: identity.owner });
        if (proposal.status !== 200) return response.custom({ statusCode: proposal.status, body: proposal.body });
        if (action === 'apply') {
          const agents = await managerRead(context, '/agents', { agents_list: proposal.body.agent_id, limit: 1 });
          if (!agents.length || !agentGroups(agents[0]).includes(proposal.body.group_name)) {
            return response.customError({ statusCode: 409, body: { message: 'Agent group membership changed; validate again' } });
          }
        }
        const result = await policyRequest('apply', '/' + action, { proposal_id: request.params.id, owner: identity.owner });
        return response.custom({ statusCode: result.status, headers: { 'Cache-Control': 'no-store' }, body: result.body });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Policy apply service unavailable' } });
      }
    };
    router.post({ path: PREFIX + '/policies/agent-sca/proposals', validate: { body: schema.object({ agent_id: schema.string() }) } },
      async (context: any, request: any, response: any) => {
        if (!AGENT_ID.test(request.body.agent_id)) return response.badRequest();
        try {
          const identity = await currentIdentity(context);
          if (!identity) return response.unauthorized();
          if (!adminAllowed(identity)) return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
          const agents = await managerRead(context, '/agents', { agents_list: request.body.agent_id, limit: 1 });
          if (!agents.length) return response.notFound();
          const result = await policyRequest('validator', '/proposals', { agent_id: request.body.agent_id, owner: identity.owner });
          return response.custom({ statusCode: result.status, headers: { 'Cache-Control': 'no-store' }, body: result.body });
        } catch { return response.customError({ statusCode: 503, body: { message: 'Policy proposals unavailable' } }); }
      });
    router.get({ path: PREFIX + '/policies/agent-sca/proposals/{id}', validate: { params: schema.object({ id: schema.string() }) } }, proposalRoute('status'));
    router.post({ path: PREFIX + '/policies/agent-sca/proposals/{id}/apply', validate: { params: schema.object({ id: schema.string() }), body: schema.object({}) } }, proposalRoute('apply'));
    router.post({ path: PREFIX + '/policies/agent-sca/proposals/{id}/rollback', validate: { params: schema.object({ id: schema.string() }), body: schema.object({}) } }, proposalRoute('rollback'));

    router.post({ path: PREFIX + '/investigations', validate: { body: schema.object({
      source_type: schema.string(), index: schema.maybe(schema.string({ maxLength: 128 })),
      id: schema.maybe(schema.string({ maxLength: 512 })), agent_id: schema.maybe(schema.string({ maxLength: 6 })),
    }) } }, async (context: any, request: any, response: any) => {
      try {
        const identity = await currentIdentity(context);
        if (!identity) return response.unauthorized();
        const { source_type, index, id, agent_id } = request.body;
        let evidence: any;
        let sourceRef: string;
        let title: string;
        if (source_type === 'agent') {
          if (!AGENT_ID.test(agent_id || '')) return response.badRequest();
          const agents = await managerRead(context, '/agents', { agents_list: agent_id, limit: 1 });
          if (!agents.length) return response.notFound();
          const policies = await managerRead(context, `/sca/${agent_id}`, { limit: 20 });
          const failedChecks: any[] = [];
          for (const policy of policies.slice(0, 2)) {
            if (typeof policy.policy_id !== 'string' || !/^[a-zA-Z0-9._-]{1,128}$/.test(policy.policy_id)) continue;
            try {
              const checks = await managerRead(context, `/sca/${agent_id}/checks/${policy.policy_id}`, { limit: 5, q: 'result=failed' });
              failedChecks.push(...checks.slice(0, 5).map((check: any) => ({
                policy_id: policy.policy_id, id: check.id, title: String(check.title || '').slice(0, 140),
                remediation: String(check.remediation || '').slice(0, 180),
              })));
            } catch { /* Keep the policy summary if individual checks are unavailable. */ }
          }
          sourceRef = `agent:${agent_id}`;
          title = `Agent ${agent_id} posture`;
          evidence = { source_ref: sourceRef, agent: {
            id: agents[0].id, name: agents[0].name, status: agents[0].status,
            os: agents[0].os?.name, group_config_status: agents[0].group_config_status,
          }, sca_policies: policies.slice(0, 8).map((item: any) => ({
            policy_id: item.policy_id, name: String(item.name || '').slice(0, 120), score: item.score,
            pass: item.pass, fail: item.fail, invalid: item.invalid, total_checks: item.total_checks,
          })), failed_checks: failedChecks.slice(0, 6) };
        } else if (source_type === 'alert' || source_type === 'archive') {
          if (!INDEX.test(index || '') || !id || (source_type === 'alert' && !index.startsWith('wazuh-alerts-')) ||
            (source_type === 'archive' && !index.startsWith('wazuh-archives-'))) return response.badRequest();
          const result = await context.core.opensearch.client.asCurrentUser.transport.request({
            method: 'GET', path: `/${index}/_doc/${encodeURIComponent(id)}`,
          });
          const data = result.body || result;
          if (!data.found) return response.notFound();
          sourceRef = `${index}/${id}`;
          title = `${source_type === 'alert' ? 'Alert' : 'Event'} · ${(data._source?.rule?.description || data._source?.agent?.name || id).slice(0, 65)}`;
          evidence = { source_ref: sourceRef, record: conciseSource(data._source || {}) };
        } else return response.badRequest();
        // The orchestrator caps persisted evidence at 6,000 characters. Long rule
        // descriptions and SCA titles vary by policy, so keep a bounded summary.
        if (JSON.stringify(evidence).length > 5800 && source_type === 'agent') {
          evidence.failed_checks = evidence.failed_checks.slice(0, 3);
          evidence.sca_policies = evidence.sca_policies.slice(0, 5);
        }
        if (JSON.stringify(evidence).length > 5800) {
          return response.customError({ statusCode: 413, body: { message: 'Selected evidence is too large to save' } });
        }
        const upstream = await proxy('POST', '/api/investigations', identity.owner, {
          source_type, source_ref: sourceRef, title, evidence,
        });
        return response.custom({ statusCode: upstream.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: upstream.body });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Investigation source unavailable or not permitted' } });
      }
    });
    return {};
  }

  start() { return {}; }
  stop() {}
}
