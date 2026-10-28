import { createHash } from 'crypto';
import { IncomingMessage, request as httpRequest } from 'http';
import { schema } from '@osd/config-schema';
import { CoreSetup, Plugin, PluginInitializerContext } from 'opensearch_dashboards/server';

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

function validatePolicy(payload: unknown): Promise<{ status: number; body: any }> {
  const token = process.env.ASSISTANT_POLICY_TOKEN || '';
  if (token.length < 32) return Promise.reject(new Error('policy token missing'));
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const upstream = httpRequest({
      hostname: '127.0.0.1', port: 8766, method: 'POST', path: '/validate', timeout: 20000,
      headers: { 'X-Policy-Token': token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (result) => {
      const chunks: Buffer[] = [];
      result.on('data', (chunk: Buffer) => chunks.push(chunk));
      result.on('end', () => {
        try { resolve({ status: result.statusCode || 502, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { reject(new Error('invalid policy validator response')); }
      });
    });
    upstream.on('timeout', () => upstream.destroy(new Error('policy validation timeout')));
    upstream.on('error', reject);
    upstream.end(body);
  });
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
            const allowed = new Set((process.env.ASSISTANT_ADMIN_ROLES || 'all_access').split(',').map((role) => role.trim()).filter(Boolean));
            if (!identity.roles.some((role: unknown) => typeof role === 'string' && allowed.has(role))) {
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
    router.get({ path: PREFIX + '/sessions', validate: false }, handle('GET', '/sessions', () => '/api/sessions'));
    router.post({ path: PREFIX + '/sessions', validate: { body: schema.object({}) } }, handle('POST', '/sessions', () => '/api/sessions'));
    router.delete({ path: PREFIX + '/sessions', validate: false }, handle('DELETE', '/sessions', () => '/api/sessions'));
    router.get({ path: PREFIX + '/settings', validate: false }, handle('GET', '/settings', () => '/api/settings'));
    router.post({ path: PREFIX + '/settings', validate: { body: schema.object({ retention_days: schema.number({ min: 0, max: 365 }) }) } },
      handle('POST', '/settings', () => '/api/settings'));
    router.get({ path: PREFIX + '/provider/config', validate: false }, handle('GET', '/provider/config', () => '/api/provider/config', true));
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
      body: schema.object({ content: schema.string({ minLength: 1, maxLength: 4000 }) }),
    } }, handle('POST', '/messages', (request) => {
      if (!SESSION_ID.test(request.params.id)) throw new Error('invalid session');
      return `/api/sessions/${request.params.id}/messages`;
    }));

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
        const allowed = new Set((process.env.ASSISTANT_ADMIN_ROLES || 'all_access').split(',').map((role) => role.trim()).filter(Boolean));
        if (!identity.roles.some((role: unknown) => typeof role === 'string' && allowed.has(role))) {
          return response.customError({ statusCode: 403, body: { message: 'Administrator access required' } });
        }
        const agents = await managerRead(context, '/agents', { agents_list: agent_id, limit: 1 });
        if (!agents.length) return response.notFound();
        const groups = agentGroups(agents[0]);
        if (!groups.includes(group)) return response.badRequest();
        const checked = await validatePolicy({ group, settings });
        return response.custom({ statusCode: checked.status, headers: { 'Cache-Control': 'no-store' }, body: checked.body });
      } catch {
        return response.customError({ statusCode: 503, body: { message: 'Wazuh policy validation unavailable' } });
      }
    });

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
