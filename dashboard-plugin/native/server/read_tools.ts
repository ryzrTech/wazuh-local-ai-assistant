type ManagerRead = (context: any, path: string, params?: Record<string, unknown>) => Promise<any[]>;

const AGENT_ID = /^\d{1,6}$/;
const RULE_ID = /^\d{1,6}$/;
const POLICY_ID = /^[A-Za-z0-9._-]{1,128}$/;
const GROUP_ID = /^[A-Za-z0-9_.-]{1,64}$/;
const EXTRA_SOURCES = ['agents', 'rootcheck', 'fim', 'services', 'users', 'groups', 'network_interfaces',
  'network_addresses', 'network_protocols', 'browser_extensions', 'hotfixes', 'hardware', 'os', 'agent_daemons',
  'agent_rootcheck_config', 'agent_fim_config', 'sca_checks', 'ciscat', 'rules', 'decoders', 'agent_groups',
  'manager_status', 'manager_info', 'manager_log_summary', 'manager_active_response', 'manager_commands',
  'cluster_status', 'tasks'] as const;
type ExtraSource = typeof EXTRA_SOURCES[number];

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
    srcip: source.data?.srcip ? String(source.data.srcip).slice(0, 80) : source.srcip ? String(source.srcip).slice(0, 80) : undefined,
    full_log: typeof source.full_log === 'string' ? source.full_log.slice(0, 900) : undefined,
  };
}

function inventoryArgs(raw: string, keys: string[]) {
  const args = objectArgs(raw, ['agent_id', 'offset', ...keys]);
  if (typeof args.agent_id !== 'string' || !AGENT_ID.test(args.agent_id)) throw new Error('Invalid agent ID');
  if (args.offset !== undefined && (!Number.isInteger(args.offset) || args.offset < 0 || args.offset > 5000)) throw new Error('Invalid inventory offset');
  if (args.search !== undefined && (typeof args.search !== 'string' || args.search.length > 80 || /[\x00-\x1f\x7f]/.test(args.search))) throw new Error('Invalid inventory search');
  return args;
}

const short = (value: unknown, limit = 120) => String(value ?? '').slice(0, limit);

function boundedRecord(value: any, depth = 0): any {
  if (typeof value === 'string') return value.slice(0, 180);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= 3) return '[nested data omitted]';
  if (Array.isArray(value)) return value.slice(0, 6).map((item) => boundedRecord(item, depth + 1));
  if (!value || typeof value !== 'object') return undefined;
  const result: Record<string, any> = {};
  for (const [key, item] of Object.entries(value).slice(0, 28)) {
    if (/password|passwd|secret|token|credential|private.key|api.key|authorization|certificate/i.test(key)) continue;
    result[key.slice(0, 80)] = boundedRecord(item, depth + 1);
  }
  return result;
}

export function capabilities(admin: boolean) {
  return {
    read_tools: ['search_alerts', 'search_raw_events', 'get_agent', 'get_sca_results',
      'get_software_inventory', 'get_processes', 'get_ports', 'get_vulnerabilities', 'get_wazuh_data'],
    wazuh_data_sources: EXTRA_SOURCES,
    scope: 'Read-only Wazuh data through the signed-in user’s permissions',
    limits: { search_hours: 720, search_results: 10, inventory_results: 10, wazuh_data_results: 5,
      inventory_offset_max: 5000, raw_event_retention_days: 30 },
    signed_in_user_can_review_agent_sca_changes: admin,
    chat_can_stage_agent_sca_proposals: admin,
    chat_can_stage_response_actions: admin,
    reviewed_response_ui: admin ? 'A signed-in administrator can review and approve one-agent restart or Linux firewall-drop proposals in AI investigations' : 'Administrator access required',
    policy_validation: admin ? 'Only agent and SCA group-setting proposals can currently be syntax-checked in AI investigations' : 'Administrator access required for agent and SCA proposals',
    reviewed_policy_ui: admin ? 'This signed-in user can apply or roll back reviewed agent and SCA group settings in AI investigations' : 'Administrator access required for reviewed agent and SCA changes',
    chat_policy_apply: false, chat_active_response: false, chat_arbitrary_commands: false,
    exclusion_rule_validation: false, exclusion_rule_apply: false,
    note: 'The chat-policy flags describe model tools, not the signed-in user’s administrator role. No exclusion validator or apply workflow is installed. Do not claim an exclusion was syntax-checked. A read tool can be available even when this user lacks permission to read a particular source.',
  };
}

export async function executeReadTool(context: any, name: string, rawArgs: string, admin: boolean, managerRead: ManagerRead) {
  if (name === 'get_capabilities') {
    const args = objectArgs(rawArgs, []);
    return { arguments: args, count: 1, data: capabilities(admin) };
  }
  if (name === 'get_wazuh_data') {
    const args = objectArgs(rawArgs, ['source', 'agent_id', 'group_id', 'rule_id', 'policy_id', 'search', 'offset']);
    if (!EXTRA_SOURCES.includes(args.source as ExtraSource)) throw new Error('Unsupported Wazuh data source');
    if (args.agent_id !== undefined && (typeof args.agent_id !== 'string' || !AGENT_ID.test(args.agent_id))) throw new Error('Invalid agent ID');
    if (args.group_id !== undefined && (typeof args.group_id !== 'string' || !GROUP_ID.test(args.group_id) || args.group_id === '.' || args.group_id === '..')) throw new Error('Invalid group ID');
    if (args.rule_id !== undefined && (typeof args.rule_id !== 'string' || !RULE_ID.test(args.rule_id))) throw new Error('Invalid rule ID');
    if (args.policy_id !== undefined && (typeof args.policy_id !== 'string' || !POLICY_ID.test(args.policy_id))) throw new Error('Invalid policy ID');
    if (args.search !== undefined && (typeof args.search !== 'string' || args.search.length > 80 || /[\x00-\x1f\x7f]/.test(args.search))) throw new Error('Invalid search');
    if (args.offset !== undefined && (!Number.isInteger(args.offset) || args.offset < 0 || args.offset > 5000)) throw new Error('Invalid offset');
    const source = args.source as ExtraSource;
    const agentPaths: Partial<Record<ExtraSource, string>> = {
      rootcheck: 'rootcheck', fim: 'syscheck', services: 'syscollector/services', users: 'syscollector/users',
      groups: 'syscollector/groups', network_interfaces: 'syscollector/netiface',
      network_addresses: 'syscollector/netaddr', network_protocols: 'syscollector/netproto',
      browser_extensions: 'syscollector/browser_extensions',
      hotfixes: 'syscollector/hotfixes', hardware: 'syscollector/hardware', os: 'syscollector/os',
      agent_daemons: 'daemons/stats', agent_rootcheck_config: 'config/syscheck/rootcheck',
      agent_fim_config: 'config/syscheck/syscheck', sca_checks: 'sca/checks', ciscat: 'ciscat/results',
    };
    const requiresAgent = source in agentPaths;
    if (requiresAgent !== !!args.agent_id) throw new Error(requiresAgent ? 'Agent ID required' : 'Agent ID is not used for this source');
    if ((source === 'agent_groups') !== !!args.group_id) throw new Error(source === 'agent_groups' ? 'Group ID required' : 'Group ID is not used for this source');
    if (args.rule_id && source !== 'rules') throw new Error('Rule ID is only valid for rules');
    if ((source === 'sca_checks') !== !!args.policy_id) throw new Error(source === 'sca_checks' ? 'Policy ID required' : 'Policy ID is not used for this source');
    if (args.search && !['agents', 'rootcheck', 'fim', 'services', 'users', 'groups', 'network_interfaces',
      'network_addresses', 'network_protocols', 'browser_extensions', 'hotfixes', 'sca_checks', 'ciscat',
      'rules', 'decoders', 'agent_groups'].includes(source)) throw new Error('Search is not supported for this source');
    const unpaged = ['hardware', 'os', 'agent_daemons', 'agent_rootcheck_config', 'agent_fim_config',
      'manager_status', 'manager_info', 'manager_log_summary', 'manager_active_response', 'manager_commands',
      'cluster_status'].includes(source);
    if (unpaged && args.offset) throw new Error('Offset is not supported for this source');
    const paths: Partial<Record<ExtraSource, string>> = {
      agents: '/agents', rules: '/rules', decoders: '/decoders', manager_status: '/manager/status',
      manager_info: '/manager/info', manager_log_summary: '/manager/logs/summary',
      manager_active_response: '/manager/configuration/analysis/active_response',
      manager_commands: '/manager/configuration/analysis/command',
      cluster_status: '/cluster/status', tasks: '/tasks/status',
    };
    let path: string | undefined;
    if (source === 'agent_daemons') path = `/agents/${args.agent_id}/daemons/stats`;
    else if (source === 'agent_rootcheck_config') path = `/agents/${args.agent_id}/config/syscheck/rootcheck`;
    else if (source === 'agent_fim_config') path = `/agents/${args.agent_id}/config/syscheck/syscheck`;
    else if (source === 'sca_checks') path = `/sca/${args.agent_id}/checks/${args.policy_id}`;
    else if (source === 'ciscat') path = `/ciscat/${args.agent_id}/results`;
    else if (source === 'rootcheck') path = `/rootcheck/${args.agent_id}`;
    else if (source === 'fim') path = `/syscheck/${args.agent_id}`;
    else if (requiresAgent) path = `/syscollector/${args.agent_id}/${agentPaths[source]!.split('/')[1]}`;
    else if (source === 'agent_groups') path = `/groups/${args.group_id}/agents`;
    else path = paths[source];
    if (!path) throw new Error('Unsupported Wazuh path');
    const params: Record<string, unknown> = unpaged ? {} : { limit: 6, offset: args.offset || 0 };
    if (args.search) params.search = args.search;
    if (args.rule_id) params.rule_ids = args.rule_id;
    const raw = await managerRead(context, path, params);
    const items = Array.isArray(raw) ? raw : raw ? [raw] : [];
    const records = items.slice(0, 5).map((item: any, index: number) => ({
      ...(boundedRecord(item) || {}),
      source_ref: `${source}:${args.agent_id || args.group_id || 'manager'}/${(args.offset || 0) + index}`,
    }));
    return { arguments: args, count: records.length, data: { retrieved_at: new Date().toISOString(),
      source, offset: args.offset || 0, more_available: items.length > 5,
      note: 'Records are bounded; strings and nested arrays may be shortened. An empty page is not proof that the source is complete.',
      records } };
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
        _source: ['timestamp', 'agent.id', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'location', 'full_log', 'data.srcip', 'srcip'],
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
  if (name === 'get_software_inventory' || name === 'get_processes' || name === 'get_ports') {
    const args = inventoryArgs(rawArgs, name === 'get_ports' ? ['local_port', 'search'] : name === 'get_processes' ? ['pid', 'search'] : ['search']);
    if (args.local_port !== undefined && (!Number.isInteger(args.local_port) || args.local_port < 1 || args.local_port > 65535)) throw new Error('Invalid port');
    if (args.pid !== undefined && (!Number.isInteger(args.pid) || args.pid < 0 || args.pid > 2147483647)) throw new Error('Invalid PID');
    const kind = name === 'get_software_inventory' ? 'packages' : name === 'get_processes' ? 'processes' : 'ports';
    const params: Record<string, unknown> = { limit: 11, offset: args.offset || 0 };
    if (args.search) params.search = args.search;
    if (args.pid !== undefined) params.pid = String(args.pid);
    if (args.local_port !== undefined) params.q = `local.port=${args.local_port}`;
    const items = await managerRead(context, `/syscollector/${args.agent_id}/${kind}`, params);
    const records = items.slice(0, 10).map((item: any, index: number) => {
      const source_ref = `agent:${args.agent_id}/syscollector:${kind}/${(args.offset || 0) + index}`;
      const scan_time = short(item.scan?.time, 40);
      if (kind === 'packages') return { source_ref, scan_time, name: short(item.name), version: short(item.version),
        vendor: short(item.vendor), architecture: short(item.architecture, 40), description: short(item.description, 180),
        location: short(item.location, 180), install_time: short(item.install_time, 40) };
      if (kind === 'processes') return { source_ref, scan_time, pid: item.pid, ppid: item.ppid,
        name: short(item.name), cmd: short(item.cmd, 180), user: short(item.euser || item.ruser, 80),
        state: short(item.state, 40), start_time: short(item.start_time, 40) };
      return { source_ref, scan_time, protocol: short(item.protocol, 24), state: short(item.state, 40),
        local_ip: short(item.local?.ip, 80), local_port: item.local?.port, remote_ip: short(item.remote?.ip, 80),
        remote_port: item.remote?.port, pid: item.pid, process: short(item.process) };
    });
    return { arguments: args, count: records.length, data: { retrieved_at: new Date().toISOString(),
      source_ref: `agent:${args.agent_id}`, inventory: kind, offset: args.offset || 0,
      more_available: items.length > 10, note: 'Syscollector data is a scan snapshot, not a live endpoint query.', records } };
  }
  if (name === 'get_vulnerabilities') {
    const args = inventoryArgs(rawArgs, ['min_score']);
    if (args.min_score !== undefined && (typeof args.min_score !== 'number' || !Number.isFinite(args.min_score) || args.min_score < 0 || args.min_score > 10)) throw new Error('Invalid minimum score');
    const filter: any[] = [{ term: { 'agent.id': args.agent_id } }];
    if (args.min_score !== undefined) filter.push({ range: { 'vulnerability.score.base': { gte: args.min_score } } });
    const result = await context.core.opensearch.client.asCurrentUser.transport.request({
      method: 'POST', path: '/wazuh-states-vulnerabilities-*/_search', body: {
        from: args.offset || 0, size: 11, track_total_hits: false, timeout: '5s',
        sort: [{ 'vulnerability.score.base': { order: 'desc', missing: '_last' } },
          { 'vulnerability.detected_at': { order: 'desc', missing: '_last' } }],
        _source: ['agent.id', 'package.name', 'package.version', 'vulnerability.id', 'vulnerability.severity',
          'vulnerability.score.base', 'vulnerability.description', 'vulnerability.detected_at', 'vulnerability.reference'],
        query: { bool: { filter } },
      },
    });
    const hits = (result.body || result).hits?.hits || [];
    const records = hits.slice(0, 10).map((hit: any) => {
      const source = hit._source || {};
      return { source_ref: `${short(hit._index, 128)}/${short(hit._id, 256)}`,
        agent_id: short(source.agent?.id, 12), cve: short(source.vulnerability?.id, 80),
        severity: short(source.vulnerability?.severity, 40), score: source.vulnerability?.score?.base,
        detected_at: short(source.vulnerability?.detected_at, 40),
        package: short(source.package?.name), version: short(source.package?.version),
        description: short(source.vulnerability?.description, 300), reference: short(source.vulnerability?.reference, 180) };
    });
    return { arguments: args, count: records.length, data: { retrieved_at: new Date().toISOString(),
      offset: args.offset || 0, more_available: hits.length > 10, records } };
  }
  throw new Error('Unsupported read tool');
}
