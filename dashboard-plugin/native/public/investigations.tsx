import React, { useEffect, useState } from 'react';
import { EuiButton, EuiLoadingSpinner } from '@elastic/eui';
import { CoreStart } from 'opensearch_dashboards/public';
import { AssistantMarkdown } from './markdown';

type SourceType = 'alert' | 'archive' | 'agent';
type RecordItem = { id: string; index: string; source: any };
type Agent = { id: string; name: string; status: string; os?: string; group_config_status?: string; groups: string[] };
type Investigation = { session_id: string; source_type: string; source_ref: string; title: string; updated_at: string };
type ScaSettings = { enabled: string; scan_on_start: string; skip_nfs: string; interval: string };
type Proposal = { group: string; base_sha256: string; diff: string; valid: boolean; validator_output: string;
  scope: string; next_check: string; proposal_id?: string; expires_at?: string; status?: string; applied_at?: string };
type StoredProposal = { id: string; group_name: string; status: string; created_at: string; applied_at?: string;
  diff: string; base_sha256: string; validator_output: string; expires_at: string };
type ActionProposal = { id: string; action: 'restart_agent' | 'block_ip'; agent_id: string; target_ip: string;
  evidence_ref: string; reason: string; status: string; created_at: string; expires_at: string; result: string };

export function Investigations({ core }: { core: CoreStart }) {
  const [sourceType, setSourceType] = useState<SourceType>('alert');
  const [hours, setHours] = useState(24);
  const [minLevel, setMinLevel] = useState(7);
  const [agentFilter, setAgentFilter] = useState('');
  const [records, setRecords] = useState<RecordItem[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<RecordItem | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [currentCase, setCurrentCase] = useState<Investigation | null>(null);
  const [answer, setAnswer] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [group, setGroup] = useState('');
  const [scaSettings, setScaSettings] = useState<ScaSettings>({ enabled: 'yes', scan_on_start: 'yes', skip_nfs: 'yes', interval: '12h' });
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [validating, setValidating] = useState(false);
  const [applying, setApplying] = useState(false);
  const [verification, setVerification] = useState('');
  const [storedProposals, setStoredProposals] = useState<StoredProposal[]>([]);
  const [actionProposals, setActionProposals] = useState<ActionProposal[]>([]);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionStatus, setActionStatus] = useState('');

  const endpoint = (path: string) => core.http.basePath.prepend('/api/wazuh_local_ai' + path);
  async function api(path: string, options: RequestInit = {}) {
    const response = await fetch(endpoint(path), {
      credentials: 'same-origin', cache: 'no-store',
      headers: { 'osd-xsrf': 'wazuh-local-ai', 'Content-Type': 'application/json' }, ...options,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || data.message || `Request failed (${response.status})`);
    return data;
  }

  async function loadCases() {
    const data = await api('/investigations');
    setInvestigations(data.investigations || []);
  }

  async function loadActions() {
    const data = await api('/actions/proposals');
    setActionProposals(data.proposals || []);
  }

  async function reviewAction(item: ActionProposal, decision: 'approve' | 'deny') {
    const detail = item.action === 'restart_agent' ? `restart agent ${item.agent_id}` :
      `send firewall-drop for ${item.target_ip} to agent ${item.agent_id}`;
    if (!window.confirm(`${decision === 'approve' ? 'Approve' : 'Deny'} this exact Wazuh action: ${detail}?\n\nReason: ${item.reason}${item.evidence_ref ? `\nAlert: ${item.evidence_ref}` : ''}`)) return;
    setActionBusy(true); setActionStatus('');
    try {
      const result = await api(`/actions/proposals/${item.id}/${decision}`, { method: 'POST', body: '{}' });
      setActionStatus(result.result || result.status || 'Action reviewed.');
      await loadActions();
    } catch (cause) { setActionStatus(cause instanceof Error ? cause.message : 'Action review failed.'); }
    finally { setActionBusy(false); }
  }

  async function loadSource(kind: SourceType = sourceType) {
    setLoading(true); setError(''); setSelectedRecord(null); setSelectedAgent(null); setPolicies([]); setCurrentCase(null); setAnswer(''); setProposal(null); setVerification(''); setStoredProposals([]);
    try {
      if (kind === 'agent') {
        const data = await api('/agents');
        setAgents(data.agents || []);
      } else {
        const data = await api('/records/search', { method: 'POST', body: JSON.stringify({
          source_type: kind, hours, min_level: minLevel, agent_id: agentFilter.trim() || undefined,
        }) });
        setRecords(data.records || []);
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not load Wazuh data.'); }
    finally { setLoading(false); }
  }

  useEffect(() => { loadCases().catch(() => undefined); loadActions().catch(() => undefined); loadSource('alert'); }, []);

  async function selectAgent(agent: Agent) {
    setSelectedAgent(agent); setSelectedRecord(null); setCurrentCase(null); setAnswer(''); setPolicies([]); setError(''); setProposal(null); setVerification(''); setStoredProposals([]); setGroup(agent.groups?.[0] || '');
    try { const data = await api(`/agents/${agent.id}/sca`); setPolicies(data.policies || []); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'SCA results unavailable.'); }
    await loadProposals(agent.id).catch(() => undefined);
  }

  async function loadProposals(agentId: string) {
    const data = await api('/policies/agent-sca/proposals', { method: 'POST', body: JSON.stringify({ agent_id: agentId }) });
    setStoredProposals(data.proposals || []);
  }

  function openProposal(item: StoredProposal) {
    setProposal({ ...item, group: item.group_name, proposal_id: item.id, valid: true,
      scope: item.status === 'applied' ? `Group ${item.group_name} configuration updated; agent distribution awaits verification` :
        item.status === 'rolled_back' ? `Saved configuration restored for group ${item.group_name}; agent distribution awaits verification` :
        `All agents assigned to group ${item.group_name}; no configuration was changed`,
      next_check: 'After apply, check group synchronization and the next SCA scan' });
    setVerification('');
  }

  async function selectCase(item: Investigation) {
    setCurrentCase(item); setSelectedRecord(null); setSelectedAgent(null); setError(''); setAnswer(''); setProposal(null);
    try {
      const data = await api(`/sessions/${item.session_id}/messages`);
      const latest = [...(data.messages || [])].reverse().find((message: any) => message.role === 'assistant');
      setAnswer(latest?.content || 'No AI analysis has been saved for this investigation.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not open investigation.'); }
  }

  async function validateScaProposal() {
    if (!selectedAgent || !group) return;
    setValidating(true); setError(''); setProposal(null);
    try {
      const data = await api('/policies/agent-sca/validate', { method: 'POST', body: JSON.stringify({
        agent_id: selectedAgent.id, group, settings: scaSettings,
      }) });
      setProposal(data);
      await loadProposals(selectedAgent.id).catch(() => undefined);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not validate the SCA proposal.'); }
    finally { setValidating(false); }
  }

  async function applyScaProposal() {
    if (!proposal?.proposal_id || !proposal.valid || !selectedAgent) return;
    if (!window.confirm(`Apply the reviewed SCA settings to group “${proposal.group}”? Every agent in this group may receive the change.`)) return;
    setApplying(true); setError(''); setVerification('');
    try {
      await api(`/policies/agent-sca/proposals/${proposal.proposal_id}/apply`, { method: 'POST', body: '{}' });
      const status = await api(`/policies/agent-sca/proposals/${proposal.proposal_id}`);
      setProposal({ ...proposal, status: status.status, applied_at: status.applied_at,
        scope: `Group ${proposal.group} configuration updated; agent distribution awaits verification` });
      await loadProposals(selectedAgent.id).catch(() => undefined);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not apply the proposal.'); }
    finally { setApplying(false); }
  }

  async function rollbackScaProposal() {
    if (!proposal?.proposal_id || proposal.status !== 'applied') return;
    if (!window.confirm(`Restore the saved agent.conf for group “${proposal.group}”?`)) return;
    setApplying(true); setError(''); setVerification('');
    try {
      await api(`/policies/agent-sca/proposals/${proposal.proposal_id}/rollback`, { method: 'POST', body: '{}' });
      setProposal({ ...proposal, status: 'rolled_back', scope: `Saved configuration restored for group ${proposal.group}; agent distribution awaits verification` });
      if (selectedAgent) await loadProposals(selectedAgent.id).catch(() => undefined);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not roll back the proposal.'); }
    finally { setApplying(false); }
  }

  async function checkScaVerification() {
    if (!selectedAgent || proposal?.status !== 'applied') return;
    setApplying(true); setError('');
    try {
      const [agentData, scaData] = await Promise.all([api(`/agents/${selectedAgent.id}`), api(`/agents/${selectedAgent.id}/sca`)]);
      const scans = (scaData.policies || []).map((item: any) => item.end_scan).filter(Boolean).sort();
      const latest = scans[scans.length - 1] || '';
      const laterScan = latest && proposal.applied_at && Date.parse(latest) > Date.parse(proposal.applied_at);
      setVerification(`Agent group sync: ${agentData.agent.group_config_status || 'unknown'}. Latest SCA scan: ${latest || 'none'}${laterScan ? ' (after apply)' : ' (no post-apply scan observed yet)'}.`);
      setPolicies(scaData.policies || []);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not check agent status.'); }
    finally { setApplying(false); }
  }

  async function analyze() {
    if (busy || (!selectedRecord && !selectedAgent)) return;
    setBusy(true); setError(''); setAnswer('');
    try {
      const body = selectedAgent ? { source_type: 'agent', agent_id: selectedAgent.id } : {
        source_type: sourceType, index: selectedRecord!.index, id: selectedRecord!.id,
      };
      const created = await api('/investigations', { method: 'POST', body: JSON.stringify(body) });
      await loadCases();
      setCurrentCase({ session_id: created.id, source_type: body.source_type, source_ref: selectedAgent ? `agent:${selectedAgent.id}` : `${selectedRecord!.index}/${selectedRecord!.id}`, title: selectedAgent ? `Agent ${selectedAgent.id} posture` : 'Event investigation', updated_at: new Date().toISOString() });
      const content = selectedAgent
        ? 'Assess this agent’s configuration and SCA posture. Draft specific agent or SCA setting changes to review, with evidence references, expected impact, and validation steps. Do not claim any proposal was tested or applied.'
        : 'Investigate this Wazuh record. Summarize what happened, assess confidence and severity, identify related hypotheses, and give concrete next investigation steps. Cite the supplied source reference.';
      const response = await fetch(endpoint(`/sessions/${created.id}/messages`), {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'osd-xsrf': 'wazuh-local-ai', 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      if (!response.ok || !response.body) throw new Error(`Analysis failed (${response.status})`);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = ''; let completed = false;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary: number;
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, boundary).replace(/\r/g, '');
          buffer = buffer.slice(boundary + 2);
          const event = frame.match(/^event: (.+)$/m)?.[1];
          const data = frame.match(/^data: (.+)$/m)?.[1];
          if (!data) continue;
          const payload = JSON.parse(data);
          if (event === 'delta') setAnswer((current) => current + payload.text);
          if (event === 'done') completed = true;
          if (event === 'error') throw new Error(payload.error);
        }
      }
      if (!completed) throw new Error('The model response ended early.');
      await loadCases();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not analyze this record.'); }
    finally { setBusy(false); }
  }

  const sourceLabel = sourceType === 'alert' ? 'Alerts' : sourceType === 'archive' ? 'Raw events' : 'Agents & SCA';
  return <main className="wlaInvestigations">
    <header className="wlaPageHeader">
      <div><h1>AI investigations</h1><p>Investigate Wazuh evidence, then review what the assistant found.</p></div>
      <span className="wlaReadOnly">Reviewed policy changes</span>
    </header>
    {actionProposals.some((item) => item.status === 'pending') && <section className="wlaActionQueue" aria-label="Actions requiring approval">
      <h2>Actions requiring approval</h2><p>Review each exact target and reason. Approval sends the command through your Wazuh permissions; endpoint effect must be checked separately.</p>
      {actionProposals.filter((item) => item.status === 'pending').map((item) => <div className="wlaActionRow" key={item.id}>
        <div><strong>{item.action === 'restart_agent' ? 'Restart agent' : 'Firewall drop IP'} · Agent {item.agent_id}{item.target_ip ? ` · ${item.target_ip}` : ''}</strong>
          <span>{item.reason}</span>{item.evidence_ref && <small>Alert: {item.evidence_ref}</small>}<small>Expires {new Date(item.expires_at).toLocaleString()}</small></div>
        <div className="wlaActionButtons"><EuiButton size="s" onClick={() => reviewAction(item, 'deny')} isDisabled={actionBusy}>Deny</EuiButton>
          <EuiButton size="s" fill onClick={() => reviewAction(item, 'approve')} isDisabled={actionBusy || Date.parse(item.expires_at) <= Date.now()}>Approve</EuiButton></div>
      </div>)}
    </section>}
    {actionStatus && <p className="wlaActionStatus" role="status">{actionStatus}</p>}
    <div className="wlaPageGrid">
      <aside className="wlaCaseRail" aria-label="Saved investigations">
        <div className="wlaPanelHeading"><h2>Investigations</h2><span>{investigations.length}</span></div>
        {investigations.length ? investigations.map((item) => <button key={item.session_id} className={'wlaCaseRow' + (currentCase?.session_id === item.session_id ? ' active' : '')} onClick={() => selectCase(item)}>
          <strong>{item.title}</strong><small>{item.source_type} · {item.updated_at?.slice(0, 10)}</small>
        </button>) : <p className="wlaBlank">No investigations yet. Choose an alert or agent to begin.</p>}
      </aside>
      <section className="wlaSourcePanel" aria-label="Wazuh source records">
        <div className="wlaTabs" role="tablist" aria-label="Evidence source">
          {([['alert', 'Alerts'], ['archive', 'Raw events'], ['agent', 'Agents & SCA']] as const).map(([kind, label]) => <button key={kind} role="tab" aria-selected={sourceType === kind} className={sourceType === kind ? 'active' : ''} onClick={() => { setSourceType(kind); loadSource(kind); }}>{label}</button>)}
        </div>
        {sourceType !== 'agent' && <div className="wlaFilters">
          <label>Time range<select value={hours} onChange={(event) => setHours(Number(event.target.value))}><option value={1}>1 hour</option><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option></select></label>
          {sourceType === 'alert' && <label>Minimum level<select value={minLevel} onChange={(event) => setMinLevel(Number(event.target.value))}><option value={0}>All</option><option value={7}>7+</option><option value={12}>12+</option><option value={15}>15+</option></select></label>}
          <label>Agent ID<input value={agentFilter} onChange={(event) => setAgentFilter(event.target.value)} placeholder="Any" inputMode="numeric" maxLength={6} /></label>
          <EuiButton size="s" onClick={() => loadSource()} isLoading={loading}>Search</EuiButton>
        </div>}
        <div className="wlaSourceHeading"><h2>{sourceLabel}</h2><span>{sourceType === 'agent' ? agents.length : records.length} shown</span></div>
        <div className="wlaSourceList">
          {loading ? <div className="wlaLoading"><EuiLoadingSpinner size="m" /> Loading Wazuh data…</div> : sourceType === 'agent'
            ? agents.map((item) => <button key={item.id} className={'wlaRecordRow' + (selectedAgent?.id === item.id ? ' active' : '')} onClick={() => selectAgent(item)}><span className="wlaRecordTop"><strong>{item.name || item.id}</strong><small>{item.status}</small></span><span>{item.os || 'OS unavailable'} · Agent {item.id}</span></button>)
            : records.map((item) => <button key={item.index + item.id} className={'wlaRecordRow' + (selectedRecord?.id === item.id ? ' active' : '')} onClick={() => { setSelectedRecord(item); setSelectedAgent(null); setCurrentCase(null); setAnswer(''); }}><span className="wlaRecordTop"><strong>{item.source.rule?.description || item.source.location || 'Raw event'}</strong><small>{item.source.rule?.level !== undefined ? `L${item.source.rule.level}` : 'event'}</small></span><span>{item.source.agent?.name || 'Unknown agent'} · {item.source.timestamp?.replace('T', ' ').slice(0, 19) || 'Time unavailable'}</span></button>)}
          {!loading && (sourceType === 'agent' ? agents.length === 0 : records.length === 0) && <p className="wlaBlank">No {sourceLabel.toLowerCase()} found for this view.</p>}
        </div>
      </section>
      <section className="wlaDetailPanel" aria-label="Investigation detail">
        {selectedRecord || selectedAgent ? <>
          <div className="wlaPanelHeading"><h2>{selectedAgent ? 'Agent posture' : 'Event detail'}</h2><span>{selectedAgent ? `Agent ${selectedAgent.id}` : selectedRecord!.source.rule?.id || sourceType}</span></div>
          {selectedAgent ? <div className="wlaDetailContent"><h3>{selectedAgent.name}</h3><p>{selectedAgent.os || 'OS unknown'} · {selectedAgent.status}</p><h4>SCA policies</h4>{policies.length ? policies.map((item) => <div className="wlaPolicyRow" key={item.policy_id}><strong>{item.name}</strong><span>Score {item.score ?? '—'} · {item.fail ?? 0} failed · {item.pass ?? 0} passed</span></div>) : <p>No SCA policy results available for this agent.</p>}
            <div className="wlaProposalForm"><h4>Propose agent SCA settings</h4><p>Validate a candidate for the whole group, review its exact diff, then explicitly apply it. Agent sync and the next SCA scan are checked separately.</p>
              <label>Agent group<select value={group} onChange={(event) => { setGroup(event.target.value); setProposal(null); }}>{(selectedAgent.groups || []).map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
              <div className="wlaProposalChoices">
                <label>SCA<select value={scaSettings.enabled} onChange={(event) => { setScaSettings({ ...scaSettings, enabled: event.target.value }); setProposal(null); }}><option value="yes">Enabled</option><option value="no">Disabled</option></select></label>
                <label>Scan interval<select value={scaSettings.interval} onChange={(event) => { setScaSettings({ ...scaSettings, interval: event.target.value }); setProposal(null); }}>{['1h', '6h', '12h', '24h', '7d'].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                <label>Scan on start<select value={scaSettings.scan_on_start} onChange={(event) => { setScaSettings({ ...scaSettings, scan_on_start: event.target.value }); setProposal(null); }}><option value="yes">Yes</option><option value="no">No</option></select></label>
                <label>Skip NFS<select value={scaSettings.skip_nfs} onChange={(event) => { setScaSettings({ ...scaSettings, skip_nfs: event.target.value }); setProposal(null); }}><option value="yes">Yes</option><option value="no">No</option></select></label>
              </div>
              <EuiButton size="s" onClick={validateScaProposal} isLoading={validating} isDisabled={!group}>Validate proposal</EuiButton>
              {!!storedProposals.length && <div className="wlaStoredProposals"><h5>Recent proposals</h5>{storedProposals.map((item) => <button key={item.id} onClick={() => openProposal(item)}><span>{item.group_name} · {item.status}</span><small>{new Date(item.created_at).toLocaleString()}</small></button>)}</div>}
              {proposal && <div className="wlaProposalResult"><strong>{proposal.status === 'applied' ? 'Applied to group configuration' : proposal.status === 'rolled_back' ? 'Saved configuration restored' : proposal.valid ? 'Wazuh syntax check passed' : 'Wazuh syntax check failed'}</strong><p>{proposal.scope}</p><pre>{proposal.diff || 'No change from the active configuration.'}</pre><small>{proposal.validator_output.trim()}</small>
                {proposal.expires_at && proposal.status !== 'applied' && <p>Proposal expires {new Date(proposal.expires_at).toLocaleString()}.</p>}
                {proposal.valid && proposal.proposal_id && <div className="wlaProposalActions">
                  {(!proposal.status || proposal.status === 'validated') && <EuiButton size="s" fill onClick={applyScaProposal} isLoading={applying} isDisabled={!!proposal.expires_at && Date.parse(proposal.expires_at) <= Date.now()}>Apply reviewed change</EuiButton>}
                  {proposal.status === 'applied' && <><EuiButton size="s" onClick={checkScaVerification} isLoading={applying}>Check agent sync and scan</EuiButton><EuiButton size="s" color="danger" onClick={rollbackScaProposal} isLoading={applying}>Roll back</EuiButton></>}
                </div>}
                {verification && <p role="status">{verification}</p>}<p>{proposal.next_check}</p></div>}
            </div></div>
            : <div className="wlaDetailContent"><h3>{selectedRecord!.source.rule?.description || 'Raw event'}</h3><p>{selectedRecord!.source.timestamp} · {selectedRecord!.source.agent?.name || 'Unknown agent'}</p><dl><dt>Source</dt><dd>{selectedRecord!.index}/{selectedRecord!.id}</dd><dt>Rule</dt><dd>{selectedRecord!.source.rule?.id || 'No triggered rule'}</dd><dt>Location</dt><dd>{selectedRecord!.source.location || 'Unknown'}</dd></dl>{selectedRecord!.source.full_log && <pre>{selectedRecord!.source.full_log}</pre>}</div>}
          <div className="wlaDetailAction"><EuiButton size="s" fill onClick={analyze} isLoading={busy}>{selectedAgent ? 'Draft posture review' : 'Investigate with AI'}</EuiButton><small>Creates a saved, read-only investigation.</small></div>
        </> : currentCase ? <><div className="wlaPanelHeading"><h2>{currentCase.title}</h2></div><p className="wlaCaseRef">{currentCase.source_ref}</p></> : <div className="wlaDetailEmpty"><h2>Choose evidence to investigate</h2><p>Select an alert, raw event, or agent. The assistant will analyze only the selected Wazuh context and cite its source.</p></div>}
        {(answer || busy) && <div className="wlaAnalysis" aria-live="polite"><h3>AI analysis</h3><p className="wlaAnalysisStatus">{busy ? 'Analyzing selected evidence…' : 'Saved with this investigation · Review before acting'}</p><div>{answer ? <AssistantMarkdown content={answer} /> : <EuiLoadingSpinner size="m" />}</div></div>}
        {error && <p className="wlaPageError" role="alert">{error}</p>}
      </section>
    </div>
  </main>;
}
