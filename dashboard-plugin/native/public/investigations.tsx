import React, { useEffect, useState } from 'react';
import { EuiButton, EuiLoadingSpinner } from '@elastic/eui';
import { CoreStart } from 'opensearch_dashboards/public';

type SourceType = 'alert' | 'archive' | 'agent';
type RecordItem = { id: string; index: string; source: any };
type Agent = { id: string; name: string; status: string; os?: string; group_config_status?: string };
type Investigation = { session_id: string; source_type: string; source_ref: string; title: string; updated_at: string };

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

  async function loadSource(kind: SourceType = sourceType) {
    setLoading(true); setError(''); setSelectedRecord(null); setSelectedAgent(null); setPolicies([]); setCurrentCase(null); setAnswer('');
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

  useEffect(() => { loadCases().catch(() => undefined); loadSource('alert'); }, []);

  async function selectAgent(agent: Agent) {
    setSelectedAgent(agent); setSelectedRecord(null); setCurrentCase(null); setAnswer(''); setPolicies([]); setError('');
    try { const data = await api(`/agents/${agent.id}/sca`); setPolicies(data.policies || []); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'SCA results unavailable.'); }
  }

  async function selectCase(item: Investigation) {
    setCurrentCase(item); setSelectedRecord(null); setSelectedAgent(null); setError(''); setAnswer('');
    try {
      const data = await api(`/sessions/${item.session_id}/messages`);
      const latest = [...(data.messages || [])].reverse().find((message: any) => message.role === 'assistant');
      setAnswer(latest?.content || 'No AI analysis has been saved for this investigation.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not open investigation.'); }
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
      <span className="wlaReadOnly">Read-only analysis</span>
    </header>
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
          {selectedAgent ? <div className="wlaDetailContent"><h3>{selectedAgent.name}</h3><p>{selectedAgent.os || 'OS unknown'} · {selectedAgent.status}</p><h4>SCA policies</h4>{policies.length ? policies.map((item) => <div className="wlaPolicyRow" key={item.policy_id}><strong>{item.name}</strong><span>Score {item.score ?? '—'} · {item.fail ?? 0} failed · {item.pass ?? 0} passed</span></div>) : <p>No SCA policy results available for this agent.</p>}</div>
            : <div className="wlaDetailContent"><h3>{selectedRecord!.source.rule?.description || 'Raw event'}</h3><p>{selectedRecord!.source.timestamp} · {selectedRecord!.source.agent?.name || 'Unknown agent'}</p><dl><dt>Source</dt><dd>{selectedRecord!.index}/{selectedRecord!.id}</dd><dt>Rule</dt><dd>{selectedRecord!.source.rule?.id || 'No triggered rule'}</dd><dt>Location</dt><dd>{selectedRecord!.source.location || 'Unknown'}</dd></dl>{selectedRecord!.source.full_log && <pre>{selectedRecord!.source.full_log}</pre>}</div>}
          <div className="wlaDetailAction"><EuiButton size="s" fill onClick={analyze} isLoading={busy}>{selectedAgent ? 'Draft posture review' : 'Investigate with AI'}</EuiButton><small>Creates a saved, read-only investigation.</small></div>
        </> : currentCase ? <><div className="wlaPanelHeading"><h2>{currentCase.title}</h2></div><p className="wlaCaseRef">{currentCase.source_ref}</p></> : <div className="wlaDetailEmpty"><h2>Choose evidence to investigate</h2><p>Select an alert, raw event, or agent. The assistant will analyze only the selected Wazuh context and cite its source.</p></div>}
        {(answer || busy) && <div className="wlaAnalysis" aria-live="polite"><h3>AI analysis</h3><p className="wlaAnalysisStatus">{busy ? 'Analyzing selected evidence…' : 'Saved with this investigation · Review before acting'}</p><div>{answer || <EuiLoadingSpinner size="m" />}</div></div>}
        {error && <p className="wlaPageError" role="alert">{error}</p>}
      </section>
    </div>
  </main>;
}
