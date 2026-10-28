type ManagerRead = (context: any, path: string, params?: Record<string, unknown>) => Promise<any[]>;

const AGENT_ID = /^\d{1,6}$/;
const RULE_ID = /^\d{1,6}$/;
const POLICY_ID = /^[A-Za-z0-9._-]{1,128}$/;

function objectArgs(raw: string, keys: string[]): Record<string, any> {
  if (typeof raw !== 'string' || raw.length > 2048) throw new Error('Invalid tool arguments');
  let args: any;
  try { args = JSON.parse(raw); } catch { throw new Error('Invalid tool arguments'); }
  if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some((key) => !keys.includes(key))) {
    throw new Error('Invalid tool arguments');
  }
  return args;
}

function conciseSource(source: any) {
  return {
    timestamp: String(source.timestamp || '').slice(0, 40),
    agent: source.agent ? { id: String(source.agent.id || '').slice(0, 12), name: String(source.agent.name || '').slice(0, 120) } : undefined,
    rule: source.rule ? { id: String(source.rule.id || '').slice(0, 12), level: source.rule.level, description: String(source.rule.description || '').slice(0, 200) } : undefined,
    location: String(source.location || '').slice(0, 160),
    full_log: typeof source.full_log === 'string' ? source.full_log.slice(0, 900) : undefined,
  };
}

export function capabilities(admin: boolean) {
  return {
    read_tools: ['search_alerts', 'search_raw_events', 'get_agent', 'get_sca_results'],
    scope: 'Read-only Wazuh data through the signed-in user’s permissions',
    limits: { search_hours: 720, search_results: 10, raw_event_retention_days: 30 },
    policy_validation: admin ? 'Agent and SCA group-setting proposals can be syntax-checked in AI investigations' : 'Administrator access required',
    policy_apply: false, active_response: false, arbitrary_commands: false,
    note: 'A tool can be available even when this user lacks permission to read a particular source.',
  };
}

export async function executeReadTool(context: any, name: string, rawArgs: string, admin: boolean, managerRead: ManagerRead) {
  if (name === 'get_capabilities') {
    const args = objectArgs(rawArgs, []);
    return { arguments: args, count: 1, data: capabilities(admin) };
  }
  if (name === 'search_alerts' || name === 'search_raw_events') {
    const alert = name === 'search_alerts';
    const args = objectArgs(rawArgs, alert ? ['hours', 'min_level', 'agent_id', 'rule_id', 'text'] : ['hours', 'agent_id', 'text']);
    if (!Number.isInteger(args.hours) || args.hours < 1 || args.hours > 720) throw new Error('Hours must be 1–720');
    if (alert && args.min_level !== undefined && (!Number.isInteger(args.min_level) || args.min_level < 0 || args.min_level > 16)) throw new Error('Invalid alert level');
    if (args.agent_id !== undefined && (typeof args.agent_id !== 'string' || !AGENT_ID.test(args.agent_id))) throw new Error('Invalid agent ID');
    if (args.rule_id !== undefined && (typeof args.rule_id !== 'string' || !RULE_ID.test(args.rule_id))) throw new Error('Invalid rule ID');
    if (args.text !== undefined && (typeof args.text !== 'string' || args.text.length > 80 || /[\x00-\x1f\x7f]/.test(args.text))) throw new Error('Invalid search text');
    const filters: any[] = [{ range: { timestamp: { gte: `now-${args.hours}h`, lte: 'now' } } }];
    if (args.agent_id) filters.push({ term: { 'agent.id': args.agent_id } });
    if (alert) filters.push({ range: { 'rule.level': { gte: args.min_level ?? 0 } } });
    if (args.rule_id) filters.push({ term: { 'rule.id': args.rule_id } });
    const must = args.text?.trim() ? [{ multi_match: { query: args.text.trim(), fields: ['rule.description', 'full_log'], type: 'phrase' } }] : [];
    const index = alert ? 'wazuh-alerts-*' : 'wazuh-archives-*';
    const result = await context.core.opensearch.client.asCurrentUser.transport.request({
      method: 'POST', path: `/${index}/_search`, body: {
        size: 10, track_total_hits: false, timeout: '5s',
        sort: [{ timestamp: { order: 'desc' } }],
        _source: ['timestamp', 'agent.id', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'location', 'full_log'],
        query: { bool: { filter: filters, must } },
      },
    });
    const data = result.body || result;
    const records = (data.hits?.hits || []).slice(0, 10).map((hit: any) => ({
      source_ref: `${String(hit._index || '').slice(0, 128)}/${String(hit._id || '').slice(0, 256)}`,
      ...conciseSource(hit._source || {}),
    }));
    return { arguments: args, count: records.length, data: { retrieved_at: new Date().toISOString(), records } };
  }
  if (name === 'get_agent' || name === 'get_sca_results') {
    const args = objectArgs(rawArgs, ['agent_id']);
    if (typeof args.agent_id !== 'string' || !AGENT_ID.test(args.agent_id)) throw new Error('Invalid agent ID');
    const agents = await managerRead(context, '/agents', { agents_list: args.agent_id, limit: 1 });
    if (!agents.length) return { arguments: args, count: 0, data: { retrieved_at: new Date().toISOString(), records: [] } };
    const agent = agents[0];
    const sourceRef = `agent:${args.agent_id}`;
    if (name === 'get_agent') {
      const groups = Array.isArray(agent.group) ? agent.group : typeof agent.group === 'string' ? agent.group.split(',') : [];
      return { arguments: args, count: 1, data: { retrieved_at: new Date().toISOString(), source_ref: sourceRef,
        agent: { id: agent.id, name: String(agent.name || '').slice(0, 120), status: agent.status,
          os: String(agent.os?.name || '').slice(0, 120), group_config_status: agent.group_config_status,
          groups: groups.slice(0, 12).map((group: unknown) => String(group).trim().slice(0, 64)) } } };
    }
    const policies = (await managerRead(context, `/sca/${args.agent_id}`, { limit: 20 })).slice(0, 20);
    const failed: any[] = [];
    for (const policy of policies.slice(0, 2)) {
      if (typeof policy.policy_id !== 'string' || !POLICY_ID.test(policy.policy_id)) continue;
      const checks = await managerRead(context, `/sca/${args.agent_id}/checks/${policy.policy_id}`, { limit: 5, q: 'result=failed' });
      failed.push(...checks.slice(0, 5).map((check: any) => ({
        source_ref: `${sourceRef}/sca:${policy.policy_id}/check:${String(check.id || '').slice(0, 64)}`,
        title: String(check.title || '').slice(0, 140), result: check.result,
        remediation: String(check.remediation || '').slice(0, 180),
      })));
    }
    return { arguments: args, count: policies.length, data: { retrieved_at: new Date().toISOString(), source_ref: sourceRef,
      policies: policies.map((policy: any) => ({ policy_id: String(policy.policy_id || '').slice(0, 128),
        name: String(policy.name || '').slice(0, 120), score: policy.score, pass: policy.pass, fail: policy.fail,
        end_scan: policy.end_scan })), failed_checks: failed } };
  }
  throw new Error('Unsupported read tool');
}
