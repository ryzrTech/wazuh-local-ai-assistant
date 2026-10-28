import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { EuiButton, EuiButtonEmpty, EuiButtonIcon, EuiLoadingSpinner, EuiTextArea } from '@elastic/eui';
import { CoreSetup, CoreStart, Plugin } from 'opensearch_dashboards/public';
import sidebarCss from './sidebar.css';
import investigationsCss from './investigations.css';
import { Investigations } from './investigations';

type Session = { id: string; title: string };
type ChatMessage = { role: 'user' | 'assistant'; content: string; tools?: Array<{ name: string; status: string; count: number }> };

function Assistant({ core }: { core: CoreStart }) {
  const [open, setOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [enterToSend, setEnterToSend] = useState(() => localStorage.getItem('wla-enter-to-send') !== 'false');
  const [compact, setCompact] = useState(() => localStorage.getItem('wla-compact') === 'true');
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionId, setSessionId] = useState<string>('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [model, setModel] = useState('Checking…');
  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [retentionDays, setRetentionDays] = useState(0);
  const [settingsError, setSettingsError] = useState('');
  const [historyBusy, setHistoryBusy] = useState(false);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);
  const [providerAdmin, setProviderAdmin] = useState<boolean | null>(null);
  const [providerUrl, setProviderUrl] = useState('');
  const [providerKey, setProviderKey] = useState('');
  const [providerModel, setProviderModel] = useState('');
  const [providerModels, setProviderModels] = useState<string[]>([]);
  const [allowedHosts, setAllowedHosts] = useState<string[]>([]);
  const [providerBusy, setProviderBusy] = useState(false);
  const [providerStatus, setProviderStatus] = useState('');
  const [alertMode, setAlertMode] = useState('dashboard');
  const [alertLevel, setAlertLevel] = useState(12);
  const [alertUrl, setAlertUrl] = useState('');
  const [alertHost, setAlertHost] = useState('');
  const [alertConfigured, setAlertConfigured] = useState(false);
  const [alertBusy, setAlertBusy] = useState(false);
  const [alertStatus, setAlertStatus] = useState('');
  const endpoint = (path: string) => core.http.basePath.prepend('/api/wazuh_local_ai' + path);

  useEffect(() => { localStorage.setItem('wla-enter-to-send', String(enterToSend)); }, [enterToSend]);
  useEffect(() => { localStorage.setItem('wla-compact', String(compact)); }, [compact]);

  async function api(path: string, options: RequestInit = {}) {
    const result = await fetch(endpoint(path), {
      credentials: 'same-origin', cache: 'no-store',
      headers: { 'osd-xsrf': 'wazuh-local-ai', 'Content-Type': 'application/json' }, ...options,
    });
    const data = await result.json().catch(() => ({}));
    if (!result.ok) throw new Error(data.error || data.message || `Assistant request failed (${result.status})`);
    return data;
  }

  async function refreshSessions() {
    const data = await api('/sessions');
    setSessions(data.sessions);
    return data.sessions as Session[];
  }

  async function selectSession(id: string) {
    if (!id) { setSessionId(''); setMessages([]); return; }
    const data = await api(`/sessions/${id}/messages`);
    setSessionId(id);
    setMessages(data.messages.map((item: ChatMessage) => ({ role: item.role, content: item.content })));
  }

  async function createSession() {
    const data = await api('/sessions', { method: 'POST', body: '{}' });
    await refreshSessions();
    await selectSession(data.id);
    return data.id as string;
  }

  useEffect(() => {
    if (!open) return;
    let active = true;
    (async () => {
      try {
        const data = await api('/models');
        if (active) setModel(data.selected);
      } catch { if (active) setModel('Unavailable'); }
      try {
        const list = await refreshSessions();
        if (active && list.length) await selectSession(list[0].id);
      } catch { if (active) setError('Assistant service is unavailable.'); }
    })();
    return () => { active = false; };
  }, [open]);

  useEffect(() => {
    if (!open || !settingsOpen) return;
    let active = true;
    setSettingsError('');
    (async () => {
      try {
        const data = await api('/settings');
        if (active) setRetentionDays(data.retention_days);
        await refreshSessions();
      } catch (cause) { if (active) setSettingsError(cause instanceof Error ? cause.message : 'Could not load chat settings.'); }
      try {
        const data = await api('/provider/config');
        if (!active) return;
        setProviderAdmin(true);
        setProviderUrl(data.url || '');
        setProviderModel(data.model || '');
        setAllowedHosts(data.allowed_hosts || []);
        if (data.model) {
          try { const models = await api('/models'); if (active) setProviderModels(models.models || []); } catch { /* The connection test will report provider errors. */ }
        }
      } catch { if (active) setProviderAdmin(false); }
      try {
        const data = await api('/alerts/config');
        if (active) { setAlertMode(data.mode); setAlertLevel(data.min_level); setAlertHost(data.url_host || ''); setAlertConfigured(!!data.configured); }
      } catch { if (active) setAlertStatus('Alert delivery settings are unavailable.'); }
    })();
    return () => { active = false; };
  }, [open, settingsOpen]);

  async function testProvider() {
    setProviderBusy(true); setProviderStatus(''); setProviderModels([]);
    try {
      const data = await api('/provider/test', { method: 'POST', body: JSON.stringify({ url: providerUrl.trim(), key: providerKey }) });
      setProviderModels(data.models);
      if (!data.models.includes(providerModel)) setProviderModel(data.models[0]);
      setProviderStatus(`Connected. ${data.models.length} model${data.models.length === 1 ? '' : 's'} available.`);
    } catch (cause) { setProviderStatus(cause instanceof Error ? cause.message : 'Connection test failed.'); }
    finally { setProviderBusy(false); }
  }

  async function saveProvider() {
    setProviderBusy(true); setProviderStatus('');
    try {
      const data = await api('/provider/config', { method: 'POST', body: JSON.stringify({ url: providerUrl.trim(), key: providerKey, model: providerModel }) });
      setProviderKey(''); setProviderUrl(data.url); setProviderModel(data.model); setModel(data.model);
      setProviderStatus('Provider settings saved.');
    } catch (cause) { setProviderStatus(cause instanceof Error ? cause.message : 'Could not save provider settings.'); }
    finally { setProviderBusy(false); }
  }

  async function saveRetention() {
    setHistoryBusy(true); setSettingsError('');
    try {
      await api('/settings', { method: 'POST', body: JSON.stringify({ retention_days: retentionDays }) });
      const list = await refreshSessions();
      if (sessionId && !list.some((session) => session.id === sessionId)) await selectSession('');
    } catch (cause) { setSettingsError(cause instanceof Error ? cause.message : 'Could not save retention.'); }
    finally { setHistoryBusy(false); }
  }

  async function saveAlertConfig() {
    setAlertBusy(true); setAlertStatus('');
    try {
      const data = await api('/alerts/config', { method: 'POST', body: JSON.stringify({
        mode: alertMode, min_level: alertLevel, url: alertUrl.trim(),
      }) });
      setAlertMode(data.mode); setAlertLevel(data.min_level); setAlertHost(data.url_host || '');
      setAlertConfigured(!!data.configured); setAlertUrl('');
      setAlertStatus(data.mode === 'dashboard' ? 'New alerts remain in Wazuh. External delivery is off.' : 'Webhook delivery enabled for new matching alerts.');
    } catch (cause) { setAlertStatus(cause instanceof Error ? cause.message : 'Could not save alert delivery settings.'); }
    finally { setAlertBusy(false); }
  }

  async function testAlertDelivery() {
    setAlertBusy(true); setAlertStatus('');
    try {
      await api('/alerts/test', { method: 'POST', body: '{}' });
      setAlertStatus('Synthetic test notification delivered.');
    } catch (cause) { setAlertStatus(cause instanceof Error ? cause.message : 'Test notification failed.'); }
    finally { setAlertBusy(false); }
  }

  async function deleteSession(id: string) {
    if (!window.confirm('Delete this conversation and its messages?')) return;
    setHistoryBusy(true); setSettingsError('');
    try {
      await api(`/sessions/${id}`, { method: 'DELETE' });
      if (sessionId === id) await selectSession('');
      await refreshSessions();
    } catch (cause) { setSettingsError(cause instanceof Error ? cause.message : 'Could not delete conversation.'); }
    finally { setHistoryBusy(false); }
  }

  async function deleteAllSessions() {
    setHistoryBusy(true); setSettingsError('');
    try {
      await api('/sessions', { method: 'DELETE' });
      await selectSession(''); setSessions([]); setConfirmDeleteAll(false);
    } catch (cause) { setSettingsError(cause instanceof Error ? cause.message : 'Could not delete chat history.'); }
    finally { setHistoryBusy(false); }
  }

  async function send() {
    const content = prompt.trim();
    if (!content || busy) return;
    setBusy(true); setError(''); setPrompt('');
    let id = sessionId;
    try {
      id = id || await createSession();
      setMessages((current) => [...current, { role: 'user', content }, { role: 'assistant', content: '' }]);
      const result = await fetch(endpoint(`/sessions/${id}/messages`), {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'osd-xsrf': 'wazuh-local-ai', 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      if (!result.ok || !result.body) throw new Error(`Message failed (${result.status})`);
      const reader = result.body.getReader();
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
          if (event === 'delta') setMessages((current) => {
            const copy = [...current];
            const last = copy[copy.length - 1];
            copy[copy.length - 1] = { ...last, content: last.content + payload.text };
            return copy;
          });
          if (event === 'done') completed = true;
          if (event === 'tool') setMessages((current) => {
            const copy = [...current];
            const last = copy[copy.length - 1];
            copy[copy.length - 1] = { ...last, tools: [...(last.tools || []), payload] };
            return copy;
          });
          if (event === 'error') throw new Error(payload.error);
        }
      }
      if (!completed) throw new Error('The response ended early.');
      await refreshSessions();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Assistant unavailable.');
      setPrompt(content);
      if (id) await selectSession(id).catch(() => undefined);
    } finally { setBusy(false); }
  }

  const drawer = open ? ReactDOM.createPortal(
    <aside className={'wlaDrawer' + (compact ? ' wlaCompact' : '')} aria-label="AI assistant">
      <header className="wlaHeader">
        <div className="wlaIdentity">
          <span className="wlaMark" aria-hidden="true">AI</span>
          <div><h2>AI assistant</h2><p>LOCAL ANALYSIS</p></div>
        </div>
        <div className="wlaHeaderActions">
          <EuiButtonIcon iconType="gear" aria-label={settingsOpen ? 'Back to chat' : 'Assistant settings'} title={settingsOpen ? 'Back to chat' : 'Settings'} onClick={() => { setSettingsOpen(!settingsOpen); setProviderKey(''); }} />
          <EuiButtonIcon iconType="cross" aria-label="Close assistant" title="Close" onClick={() => { setOpen(false); setSettingsOpen(false); setProviderKey(''); }} />
        </div>
      </header>
      {settingsOpen ? <section className="wlaSettings" aria-label="Assistant settings">
        <h3>Settings</h3>
        <p className="wlaSettingsIntro">Chat preferences are saved in this browser.</p>
        <label className="wlaSettingRow">
          <span><strong>Enter to send</strong><small>Use Shift+Enter for a new line.</small></span>
          <input type="checkbox" checked={enterToSend} onChange={(event) => setEnterToSend(event.target.checked)} />
        </label>
        <label className="wlaSettingRow">
          <span><strong>Compact messages</strong><small>Reduce spacing in the conversation.</small></span>
          <input type="checkbox" checked={compact} onChange={(event) => setCompact(event.target.checked)} />
        </label>
        <div className="wlaSettingsSection">
          <h4>Model connection</h4>
          <p>The provider is shared by this Dashboard. Administrators can test and save its connection.</p>
          {providerAdmin === null ? <p>Checking access…</p> : providerAdmin === false ?
            <p className="wlaSettingsNotice">Administrator access is required to configure the provider.</p> : <>
              <label className="wlaFormField">API URL
                <input type="url" value={providerUrl} placeholder="https://model-gateway.example/v1" spellCheck={false}
                  onChange={(event) => { setProviderUrl(event.target.value); setProviderModels([]); setProviderStatus(''); }} />
              </label>
              <label className="wlaFormField">API key
                <input type="password" value={providerKey} placeholder="Leave blank to use the saved key" autoComplete="new-password"
                  onChange={(event) => { setProviderKey(event.target.value); setProviderModels([]); setProviderStatus(''); }} />
              </label>
              <p className="wlaFieldHint">The key is stored on the server and is never shown again. Approved hosts: {allowedHosts.join(', ') || 'none configured'}.</p>
              <EuiButton size="s" onClick={testProvider} isLoading={providerBusy} isDisabled={!providerUrl.trim()}>Test connection</EuiButton>
              <label className="wlaFormField">Available model
                <select value={providerModel} disabled={!providerModels.length} onChange={(event) => setProviderModel(event.target.value)}>
                  {!providerModels.length && <option value="">Test the connection to load models</option>}
                  {providerModels.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <EuiButton size="s" fill onClick={saveProvider} isLoading={providerBusy} isDisabled={!providerModels.includes(providerModel)}>Save provider</EuiButton>
              {providerStatus && <p className="wlaSettingsNotice" role="status">{providerStatus}</p>}
            </>}
        </div>
        <div className="wlaSettingsSection">
          <h4>Alert delivery</h4>
          <p>Wazuh keeps new alerts in the Dashboard. Administrators can also deliver new matching alerts to a generic HTTPS webhook.</p>
          {providerAdmin === false ? <p className="wlaSettingsNotice">Administrator access is required to configure alert delivery.</p> : providerAdmin === null ? <p>Checking access…</p> : <>
            <label className="wlaFormField">Delivery
              <select value={alertMode} onChange={(event) => { setAlertMode(event.target.value); setAlertStatus(''); }}>
                <option value="dashboard">Dashboard only</option>
                <option value="webhook">HTTPS webhook</option>
              </select>
            </label>
            <label className="wlaFormField">Minimum alert level
              <select value={alertLevel} onChange={(event) => setAlertLevel(Number(event.target.value))}>
                <option value={10}>10 · High</option><option value={12}>12 · Critical</option><option value={15}>15 · Severe</option>
              </select>
            </label>
            {alertMode === 'webhook' && <label className="wlaFormField">Webhook URL
              <input type="url" value={alertUrl} placeholder={alertConfigured ? `Saved host: ${alertHost}` : 'https://hooks.example.com/wazuh'}
                spellCheck={false} autoComplete="off" onChange={(event) => { setAlertUrl(event.target.value); setAlertStatus(''); }} />
            </label>}
            <p className="wlaFieldHint">The full URL is stored only on the server and is never shown again. Delivery starts with new alerts after saving. Private hosts require a server allowlist.</p>
            <div className="wlaAlertActions">
              <EuiButton size="s" fill onClick={saveAlertConfig} isLoading={alertBusy} isDisabled={alertMode === 'webhook' && !alertUrl.trim() && !alertConfigured}>Save alert delivery</EuiButton>
              {alertMode === 'webhook' && alertConfigured && <EuiButton size="s" onClick={testAlertDelivery} isLoading={alertBusy} isDisabled={!!alertUrl.trim()}>Send test notification</EuiButton>}
            </div>
            {alertStatus && <p className="wlaSettingsNotice" role="status">{alertStatus}</p>}
          </>}
        </div>
        <div className="wlaSettingsSection">
          <h4>Chat history</h4>
          <p>Only your conversations are shown here.</p>
          <label className="wlaFormField">Keep conversations for
            <select value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))}>
              <option value={0}>Until I delete them</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
              <option value={365}>1 year</option>
            </select>
          </label>
          <p className="wlaFieldHint">Saving a shorter period deletes older conversations immediately. Expired conversations are then removed automatically.</p>
          <EuiButton size="s" onClick={saveRetention} isLoading={historyBusy}>Save retention</EuiButton>
          <div className="wlaHistoryList">
            {sessions.length ? sessions.map((session) => <div className="wlaHistoryItem" key={session.id}>
              <span title={session.title}>{session.title}</span>
              <EuiButtonIcon iconType="trash" aria-label={'Delete conversation ' + session.title} title="Delete conversation"
                isDisabled={historyBusy} onClick={() => deleteSession(session.id)} />
            </div>) : <p>No saved conversations.</p>}
          </div>
          {sessions.length > 0 && (confirmDeleteAll ? <div className="wlaDeleteConfirm">
            <span>Delete all your conversations?</span>
            <EuiButton size="s" color="danger" onClick={deleteAllSessions} isLoading={historyBusy}>Delete all</EuiButton>
            <EuiButtonEmpty size="s" onClick={() => setConfirmDeleteAll(false)}>Cancel</EuiButtonEmpty>
          </div> : <EuiButtonEmpty size="s" color="danger" onClick={() => setConfirmDeleteAll(true)}>Delete all history</EuiButtonEmpty>)}
          {settingsError && <p className="wlaSettingsError" role="alert">{settingsError}</p>}
        </div>
      </section> : <>
        <div className="wlaToolbar">
          <label className="wlaVisuallyHidden" htmlFor="wla-session">Conversation</label>
          <select id="wla-session" value={sessionId} onChange={(event) => selectSession(event.target.value)}>
            <option value="">New conversation</option>
            {sessions.map((session) => <option key={session.id} value={session.id}>{session.title}</option>)}
          </select>
          <EuiButtonEmpty className="wlaNew" size="s" iconType="plus" onClick={() => createSession().catch(() => setError('Could not start a conversation.'))}>New</EuiButtonEmpty>
        </div>
        <div className="wlaContext"><span>Security Analyst</span><span className="wlaContextDot" aria-hidden="true" /><span>{model}</span></div>
        <div className="wlaTranscript" role="log" aria-live="polite">
          {messages.length === 0 ? <div className="wlaEmpty">
            <span className="wlaEmptyMark" aria-hidden="true">✦</span>
            <h3>How can I help?</h3>
            <p>Ask me to search Wazuh alerts, raw events, agents, or SCA results.</p>
          </div> : messages.map((item, index) =>
            <article key={index} className={'wlaMessage wla-' + item.role}>
              <strong>{item.role === 'user' ? 'You' : 'Assistant'}</strong>
              {!!item.tools?.length && <div className="wlaToolTrace" aria-label="Wazuh tools used">
                {item.tools.map((tool, toolIndex) => <span key={toolIndex}>{tool.name.replace(/_/g, ' ')} · {tool.status === 'ok' ? `${tool.count} result${tool.count === 1 ? '' : 's'}` : tool.status}</span>)}
              </div>}
              <div>{item.content || (busy ? <EuiLoadingSpinner size="s" /> : '')}</div>
            </article>)}
        </div>
        {error && <div className="wlaError" role="alert">{error}</div>}
        <div className="wlaFooter">
          <div className="wlaComposer">
            <label className="wlaVisuallyHidden" htmlFor="wla-prompt">Message</label>
            <EuiTextArea id="wla-prompt" rows={3} placeholder="Ask a question…" value={prompt} maxLength={4000}
              onChange={(event) => setPrompt(event.target.value)}
              onKeyDown={(event) => { if (enterToSend && event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); } }} />
            <div className="wlaComposerActions">
              <span>{enterToSend ? 'Enter to send · Shift+Enter for a new line' : 'Use Send to submit'}</span>
              <EuiButton className="wlaSend" size="s" fill onClick={send} isLoading={busy}>Send</EuiButton>
            </div>
          </div>
          <p className="wlaScope">Read-only Wazuh tools · Results follow your signed-in permissions</p>
        </div>
      </>}
    </aside>, document.body) : null;
  return <><EuiButtonIcon className="wlaLauncherIcon" iconType="chatLeft" aria-label="AI assistant" title="AI assistant" aria-pressed={open}
    onClick={() => { setOpen(!open); if (open) { setSettingsOpen(false); setProviderKey(''); } }} />{drawer}</>;
}

export class LocalAiPublicPlugin implements Plugin {
  setup(core: CoreSetup) {
    core.application.register({
      id: 'wazuhAiInvestigations',
      title: 'AI investigations',
      appRoute: '/app/wazuh-ai-investigations',
      mount: async (params: any) => {
        const [coreStart] = await core.getStartServices();
        ReactDOM.render(<Investigations core={coreStart} />, params.element);
        return () => ReactDOM.unmountComponentAtNode(params.element);
      },
    });
    return {};
  }
  start(core: CoreStart) {
    const style = document.createElement('style');
    style.id = 'wazuh-local-ai-styles';
    style.textContent = sidebarCss + '\n' + investigationsCss;
    document.head.appendChild(style);
    core.chrome.navControls.registerRight({
      order: 1000,
      mount: (element: HTMLElement) => {
        ReactDOM.render(<Assistant core={core} />, element);
        return () => ReactDOM.unmountComponentAtNode(element);
      },
    });
    return {};
  }
  stop() { document.getElementById('wazuh-local-ai-styles')?.remove(); }
}
