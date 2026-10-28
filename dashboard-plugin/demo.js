const $ = (id) => document.getElementById(id);
const panel = $('assistant');
const toggle = $('toggle');
const transcript = $('transcript');
let currentSession = null;
let busy = false;

function setStatus(text) { $('status').textContent = text; }
function openPanel() { panel.hidden = false; toggle.setAttribute('aria-expanded', 'true'); $('prompt').focus(); }
function closePanel() { panel.hidden = true; toggle.setAttribute('aria-expanded', 'false'); toggle.focus(); }
toggle.addEventListener('click', openPanel);
$('close').addEventListener('click', closePanel);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !panel.hidden) closePanel(); });
$('width').addEventListener('input', (event) => document.documentElement.style.setProperty('--assistant-width', event.target.value + 'px'));
$('theme').addEventListener('click', () => { document.body.dataset.theme = document.body.dataset.theme === 'dark' ? 'light' : 'dark'; });

async function api(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  if (!response.ok) throw new Error('Request failed (' + response.status + ')');
  return response.json();
}

function message(role, content) {
  const node = document.createElement('div');
  node.className = 'message ' + (role === 'assistant' ? 'assistant-message' : 'user');
  const label = document.createElement('small');
  label.textContent = role === 'user' ? 'You' : 'Assistant';
  const body = document.createElement('span');
  body.textContent = content;
  node.append(label, body);
  transcript.append(node);
  transcript.scrollTop = transcript.scrollHeight;
  return body;
}

async function loadSessions() {
  const data = await api('/api/sessions');
  const nav = $('sessions');
  nav.replaceChildren();
  for (const session of data.sessions) {
    const button = document.createElement('button');
    button.type = 'button'; button.textContent = session.title;
    button.title = session.title;
    button.setAttribute('aria-current', String(session.id === currentSession));
    button.addEventListener('click', () => selectSession(session.id));
    nav.append(button);
  }
}

async function selectSession(id) {
  currentSession = id;
  const data = await api('/api/sessions/' + id + '/messages');
  transcript.replaceChildren();
  if (!data.messages.length) {
    const empty = document.createElement('p'); empty.className = 'empty';
    empty.textContent = 'Start a conversation. This prototype can explain security concepts but cannot inspect live events yet.';
    transcript.append(empty);
  } else for (const item of data.messages) message(item.role, item.content);
  await loadSessions();
}

async function newSession() {
  const data = await api('/api/sessions', { method: 'POST' });
  await selectSession(data.id);
  $('prompt').focus();
}
$('new-session').addEventListener('click', () => { newSession().catch((error) => setStatus(error.message)); });

async function send(content) {
  if (!currentSession) await newSession();
  transcript.querySelector('.empty')?.remove();
  message('user', content);
  const body = message('assistant', '');
  const response = await fetch('/api/sessions/' + currentSession + '/messages', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content })
  });
  if (!response.ok || !response.body) throw new Error('Message request failed (' + response.status + ')');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let completed = false;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let boundary;
    while ((boundary = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, boundary).replaceAll('\r', '');
      buffer = buffer.slice(boundary + 2);
      const event = frame.match(/^event: (.+)$/m)?.[1];
      const data = frame.match(/^data: (.+)$/m)?.[1];
      if (!data) continue;
      const payload = JSON.parse(data);
      if (event === 'delta') body.textContent += payload.text;
      if (event === 'done') { completed = true; setStatus('Ready'); }
      if (event === 'error') throw new Error(payload.error);
      transcript.scrollTop = transcript.scrollHeight;
    }
  }
  if (!completed) throw new Error('The model stream ended before completion');
  await loadSessions();
}

$('composer').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const content = $('prompt').value.trim();
  if (!content) return;
  busy = true; $('send').disabled = true; setStatus('Streaming response…'); $('prompt').value = '';
  try { await send(content); }
  catch (error) { setStatus(error.message); $('prompt').value = content; }
  finally { busy = false; $('send').disabled = false; $('prompt').focus(); }
});

async function init() {
  try {
    const model = await api('/api/models');
    $('model').replaceChildren(new Option(model.selected, model.selected));
  } catch { $('model').replaceChildren(new Option('Unavailable', '')); setStatus('Model discovery unavailable'); }
  try {
    const data = await api('/api/sessions');
    if (data.sessions.length) await selectSession(data.sessions[0].id);
    else await newSession();
  } catch (error) { setStatus(error.message); }
}
init();
