// ════════════════════════════════════════════════════════════════════════════
//  SecureVault — SPA controller  (app.js)
//  Zero-Knowledge client: K_enc & JWT live ONLY in the JS heap (no localStorage
//  / sessionStorage for secrets — report §3.1). The vault is decrypted in RAM,
//  mutated locally, re-encrypted and uploaded as an opaque blob.
// ════════════════════════════════════════════════════════════════════════════

const state = {
  token: null,
  username: null,
  kEnc: null,          // CryptoKey — in-memory only, never persisted
  salt: null,
  kdf: 'pbkdf2',
  vault: { entries: [], audit: [], alerts: {} },   // decrypted vault (RAM)
  events: [],
  sessionRisk: { score: 0, level: 'normal', reasons: [] },
  lastLogins: [],
  page: 'dashboard',
  catFilter: 'All',
  vaultQuery: '',
  editingId: null,
  genTab: 'random',
  alertSev: 'all',
};

const $ = id => document.getElementById(id);
const esc = s => { const d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; };

// ── API helper ──────────────────────────────────────────────────────────────
async function api(method, path, body, auth = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && state.token) headers['Authorization'] = `Bearer ${state.token}`;
  const r = await fetch('/api/v1' + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({ error: 'Network error' }));
  if (!r.ok) {
    if (r.status === 401 && auth && state.token) { toast('Session expired — sign in again', 'error'); doLogout(); }
    throw data;
  }
  return data;
}

// ── Toast / loader ────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const icons = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span>${esc(msg)}`;
  $('toasts').appendChild(el);
  setTimeout(() => { el.style.animation = 'fadeOut .25s ease forwards'; setTimeout(() => el.remove(), 250); }, 3000);
}
function showLoader(txt) { $('loader-txt').textContent = txt || 'Working…'; $('loader').classList.add('show'); }
function hideLoader() { $('loader').classList.remove('show'); }

function authMsg(msg, type) { const el = $('auth-msg'); el.className = `auth-msg ${type}`; el.textContent = msg; el.style.display = 'block'; }

// ── Time / format helpers ─────────────────────────────────────────────────────
function timeAgo(ts) {
  const d = Date.now() / 1000 - ts;
  if (d < 60) return 'just now';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return Math.floor(d / 86400) + 'd ago';
}
function fmtDate(ts) { return new Date(ts * 1000).toLocaleString(); }

// ── Theme ─────────────────────────────────────────────────────────────────────
function applyTheme(t) {
  document.body.classList.toggle('light', t === 'light');
  const ic = $('theme-icon');
  if (ic) ic.innerHTML = t === 'light'
    ? '<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/>'
    : '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>';
}
function toggleTheme() { const next = document.body.classList.contains('light') ? 'dark' : 'light'; applyTheme(next); localStorage.setItem('theme', next); }

// ── Severity model (SIEM) ───────────────────────────────────────────────────
const SEV = {
  BRUTE_FORCE: 'crit', RATE_LIMIT: 'crit',
  LOGIN_FAIL: 'high', INVALID_JWT: 'high',
  TOKEN_REFRESH: 'medium',
  LOGIN_OK: 'low', VAULT_ACCESS: 'low', VAULT_UPDATE: 'low', REGISTER: 'low', LOGOUT: 'low',
};
const sevOf = t => SEV[t] || 'info';
const sevRank = { crit: 4, high: 3, medium: 2, low: 1, info: 0 };

// ════════════════════════════════════════════════════════════════════════════
//  AUTH (zero-knowledge)
// ════════════════════════════════════════════════════════════════════════════
function switchAuthTab(tab) {
  document.querySelectorAll('.tab-btn[data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $('form-login').classList.toggle('hidden', tab !== 'login');
  $('form-register').classList.toggle('hidden', tab !== 'register');
  $('auth-msg').style.display = 'none';
}

async function doRegister(ev) {
  ev.preventDefault();
  const u = $('reg-user').value.trim();
  const p = $('reg-pw').value;
  const p2 = $('reg-pw2').value;
  const kdf = $('reg-kdf').value;
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(u)) return authMsg('Username must be 3–32 chars (letters, digits, _ -).', 'error');
  if (p.length < 12) return authMsg('Master password must be at least 12 characters.', 'error');
  if (p !== p2) return authMsg('Passwords do not match.', 'error');

  try {
    showLoader('Deriving keys & encrypting vault…');
    const salt = ZK.randomSalt();
    const { kEnc, authHash, kdf: usedKdf } = await ZK.deriveKeys(p, salt, kdf);
    const emptyVault = { entries: [], audit: [{ action: 'CREATE', detail: 'Vault created', time: Date.now() / 1000 }], alerts: {} };
    const blob = await ZK.encryptBlob(emptyVault, kEnc);
    const res = await api('POST', '/auth/register', { username: u, salt_hex: salt, auth_hash: authHash, kdf: usedKdf, blob }, false);
    if (!res.success) { hideLoader(); return authMsg(res.message || 'Registration failed', 'error'); }
    // Auto-login with the freshly derived material
    await finishLogin(u, p, salt, usedKdf, kEnc);
  } catch (e) {
    hideLoader();
    authMsg(e.error || e.message || 'Registration failed', 'error');
  }
}

async function doLogin(ev) {
  ev.preventDefault();
  const u = $('login-user').value.trim();
  const p = $('login-pw').value;
  if (!u || !p) return authMsg('Enter your username and master password.', 'error');
  try {
    showLoader('Deriving keys…');
    const meta = await api('GET', `/auth/salt?username=${encodeURIComponent(u)}`, null, false);
    const { kEnc, authHash } = await ZK.deriveKeys(p, meta.salt, meta.kdf);
    await finishLogin(u, p, meta.salt, meta.kdf, kEnc, authHash);
  } catch (e) {
    hideLoader();
    authMsg(e.error || e.message || 'Login failed', 'error');
  }
}

async function finishLogin(username, password, salt, kdf, kEnc, authHashArg) {
  let authHash = authHashArg;
  if (!authHash) ({ authHash } = await ZK.deriveKeys(password, salt, kdf));
  const res = await api('POST', '/auth/login', { username, auth_hash: authHash }, false);
  if (!res.success) { hideLoader(); return authMsg(res.message || 'Invalid credentials', 'error'); }

  state.token = res.token;
  state.username = username;
  state.kEnc = kEnc;
  state.salt = res.salt || salt;
  state.kdf = kdf;
  state.sessionRisk = res.session_risk || state.sessionRisk;

  // Download & decrypt the vault (in RAM)
  const { blob } = await api('GET', '/vault/blob');
  try {
    state.vault = await ZK.decryptBlob(blob, kEnc);
  } catch {
    hideLoader();
    return authMsg('Could not decrypt vault — wrong master password.', 'error');
  }
  state.vault.entries = state.vault.entries || [];
  state.vault.audit = state.vault.audit || [];
  state.vault.alerts = state.vault.alerts || {};

  hideLoader();
  enterApp();
}

function enterApp() {
  $('auth-screen').style.display = 'none';
  $('app').classList.add('active');
  $('user-name').textContent = state.username;
  $('user-avatar').textContent = state.username[0].toUpperCase();
  navTo('dashboard');
  refreshAll();
}

async function doLogout() {
  try { await api('POST', '/auth/logout'); } catch {}
  state.token = null; state.username = null; state.kEnc = null;
  state.vault = { entries: [], audit: [], alerts: {} };
  $('app').classList.remove('active');
  $('auth-screen').style.display = 'grid';
  $('login-pw').value = ''; $('reg-pw').value = ''; $('reg-pw2').value = '';
}

// ── Persist vault (encrypt → upload) ─────────────────────────────────────────
async function saveVault(actionMsg) {
  const blob = await ZK.encryptBlob(state.vault, state.kEnc);
  await api('PUT', '/vault/blob', { blob });
  if (actionMsg) toast(actionMsg, 'success');
}

function auditPush(action, detail) {
  state.vault.audit = state.vault.audit || [];
  state.vault.audit.push({ action, detail, time: Date.now() / 1000 });
  state.vault.audit = state.vault.audit.slice(-200);
}

// ════════════════════════════════════════════════════════════════════════════
//  NAVIGATION
// ════════════════════════════════════════════════════════════════════════════
const PAGE_META = {
  dashboard: ['Dashboard', 'Security overview of your vault'],
  vault: ['Vault', 'Your encrypted credentials'],
  generator: ['Generator', 'Create strong passwords locally'],
  alerts: ['Alert Center', 'Triage and resolve security alerts'],
  monitoring: ['Monitoring', 'System events and user activity'],
};
function navTo(page) {
  state.page = page;
  document.querySelectorAll('.nav-item[data-page]').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  $('topbar-title').textContent = PAGE_META[page][0];
  $('topbar-sub').textContent = PAGE_META[page][1];
  $('sidebar').classList.remove('open');
  if (page === 'dashboard') renderDashboard();
  if (page === 'vault') renderVault();
  if (page === 'alerts') renderAlerts();
  if (page === 'monitoring') renderMonitoring();
}

async function refreshAll() {
  try {
    const [alertsData, health] = await Promise.all([
      api('GET', '/security/alerts'),
      api('GET', '/security/audit'),
    ]);
    state.sessionRisk = alertsData.session_risk || state.sessionRisk;
    state.lastLogins = alertsData.last_logins || [];
    state.events = health.log || [];
  } catch {}
  updateBadges();
  if (state.page === 'dashboard') renderDashboard();
  if (state.page === 'alerts') renderAlerts();
  if (state.page === 'monitoring') renderMonitoring();
}

function updateBadges() {
  const vc = $('vault-count');
  vc.textContent = state.vault.entries.length;
  vc.classList.toggle('hidden', state.vault.entries.length === 0);
  const open = computeAlerts().filter(a => a.status !== 'resolved').length;
  const ac = $('alert-count');
  ac.textContent = open; ac.classList.toggle('hidden', open === 0);
}

// ════════════════════════════════════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════════════════════════════════════
function vaultHealth() {
  const e = state.vault.entries;
  if (!e.length) return { score: 100, weak: 0, reused: 0, strong: 0, total: 0 };
  const pwds = e.map(x => x.password || '');
  const scores = pwds.map(p => ZK.scorePassword(p).score);
  const weak = scores.filter(s => s < 50).length;
  const strong = scores.filter(s => s >= 80).length;
  const reused = pwds.length - new Set(pwds.filter(Boolean)).size;
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  const score = Math.max(0, Math.round(avg - (reused / pwds.length) * 30 - (weak / pwds.length) * 20));
  return { score, weak, reused, strong, total: e.length };
}

function statCard(tone, icon, val, name, trend) {
  return `<div class="card stat-card tone-${tone}">
    <div class="stat-icon">${icon}</div>
    <div class="stat-val">${val}</div>
    <div class="stat-name">${name}</div>
    ${trend ? `<div class="stat-trend muted">${trend}</div>` : ''}
  </div>`;
}

function renderDashboard() {
  const h = vaultHealth();
  const alerts = computeAlerts();
  const crit = alerts.filter(a => a.sev === 'crit').length;
  const high = alerts.filter(a => a.sev === 'high').length;
  const med = alerts.filter(a => a.sev === 'medium').length;
  const low = alerts.filter(a => a.sev === 'low').length;
  const I = {
    vault: '<svg class="icon" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    shield: '<svg class="icon" viewBox="0 0 24 24"><path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-4z"/></svg>',
    event: '<svg class="icon" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    alert: '<svg class="icon" viewBox="0 0 24 24"><path d="M10.3 3.9a2 2 0 0 1 3.4 0l8 14A2 2 0 0 1 20 21H4a2 2 0 0 1-1.7-3z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>',
    pulse: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
  };
  $('stat-cards').innerHTML =
    statCard('primary', I.vault, h.total, 'Stored credentials', `${h.strong} strong · ${h.weak} weak`) +
    statCard(h.score >= 70 ? 'ok' : h.score >= 40 ? 'warn' : 'danger', I.shield, h.score, 'Vault health score', h.reused ? `${h.reused} reused` : 'no reuse detected') +
    statCard('accent', I.event, state.events.length, 'Security events', 'last 200 logged') +
    statCard(crit ? 'danger' : 'ok', I.alert, crit, 'Critical alerts', `${high} high · ${med} medium`) +
    statCard(state.sessionRisk.score < 30 ? 'ok' : state.sessionRisk.score < 60 ? 'warn' : 'danger', I.pulse, state.sessionRisk.score, 'Session risk', state.sessionRisk.level) +
    statCard('ok', I.shield, 'ZK', 'Encryption', 'AES-256-GCM · client-side');

  // events per day (7 days)
  const now = Date.now() / 1000;
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const start = now - i * 86400;
    const d = new Date(start * 1000);
    const cnt = state.events.filter(e => Math.abs(e.ts - start) < 43200).length;
    days.push({ label: d.toLocaleDateString(undefined, { weekday: 'short' }), value: 0 });
  }
  // bucket events by day index
  state.events.forEach(e => {
    const idx = 6 - Math.floor((now - e.ts) / 86400);
    if (idx >= 0 && idx < 7) days[idx].value++;
  });
  Charts.bars('chart-events', days);

  Charts.gauge('chart-risk', state.sessionRisk.score);
  $('risk-level').textContent = state.sessionRisk.level.toUpperCase();
  $('risk-desc').textContent = state.sessionRisk.reasons.length ? state.sessionRisk.reasons.join(' · ') : 'No anomalies detected';

  Charts.donut('chart-alerts', [
    { label: 'Critical', value: crit, color: '#f43f5e' },
    { label: 'High', value: high, color: '#ef4444' },
    { label: 'Medium', value: med, color: '#f59e0b' },
    { label: 'Low', value: low, color: '#22c55e' },
  ], String(alerts.length), 'alerts');

  // activity feed = vault audit + events
  const acts = [
    ...state.vault.audit.map(a => ({ t: a.action, d: a.detail, time: a.time, cls: 'dot-primary' })),
    ...state.events.slice(0, 10).map(e => ({ t: e.event_type, d: e.detail, time: e.ts, cls: 'dot-' + sevOf(e.event_type) })),
  ].sort((a, b) => b.time - a.time).slice(0, 8);
  $('activity-feed').innerHTML = acts.length ? acts.map(a => `
    <div class="feed-item">
      <span class="feed-dot ${a.cls}"></span>
      <div class="feed-main"><div class="t">${esc(a.t)}</div><div class="d">${esc(a.d)}</div></div>
      <span class="feed-time">${timeAgo(a.time)}</span>
    </div>`).join('') : emptyState('No activity yet');
}
function emptyState(msg, sub) {
  return `<div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><h3>${esc(msg)}</h3>${sub ? `<p>${esc(sub)}</p>` : ''}</div>`;
}

// ════════════════════════════════════════════════════════════════════════════
//  VAULT
// ════════════════════════════════════════════════════════════════════════════
function categories() { return ['All', ...new Set(state.vault.entries.map(e => e.category || 'General'))]; }
function renderVault() {
  // category chips
  $('cat-chips').innerHTML = categories().map(c =>
    `<button class="chip ${c === state.catFilter ? 'active' : ''}" data-cat="${esc(c)}">${esc(c)}</button>`).join('');
  const q = state.vaultQuery.toLowerCase();
  let list = state.vault.entries.filter(e =>
    (state.catFilter === 'All' || (e.category || 'General') === state.catFilter) &&
    (!q || (e.title + ' ' + (e.username || '') + ' ' + (e.url || '')).toLowerCase().includes(q)));
  list = list.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  $('entries').innerHTML = list.length ? list.map(e => `
    <div class="entry" data-entry="${e.id}">
      <div class="entry-head">
        <div class="entry-fav">${esc((e.title || '?')[0].toUpperCase())}</div>
        <div class="grow minw0">
          <div class="entry-title">${esc(e.title)}</div>
          <div class="entry-user">${esc(e.username || '—')}</div>
        </div>
      </div>
      <div class="entry-foot">
        <span class="cat-tag">${esc(e.category || 'General')}</span>
        <span class="feed-time">${timeAgo(e.updated_at || e.created_at || Date.now() / 1000)}</span>
      </div>
    </div>`).join('') : emptyState('No entries', 'Add your first credential with “New entry”.');
}

function openEntryModal(id) {
  state.editingId = id || null;
  const e = id ? state.vault.entries.find(x => x.id === id) : null;
  $('entry-modal-title').textContent = id ? 'Edit entry' : 'New entry';
  $('e-title').value = e ? e.title : '';
  $('e-username').value = e ? (e.username || '') : '';
  $('e-password').value = e ? (e.password || '') : '';
  $('e-url').value = e ? (e.url || '') : '';
  $('e-category').value = e ? (e.category || 'General') : 'General';
  $('e-notes').value = e ? (e.notes || '') : '';
  liveStrength($('e-password').value, 'e-strength-bar', 'e-strength-label');
  openModal('entry-modal');
}

async function saveEntry() {
  const title = $('e-title').value.trim();
  if (!title) return toast('Title is required', 'error');
  const data = {
    title,
    username: $('e-username').value,
    password: $('e-password').value,
    url: $('e-url').value.trim(),
    category: $('e-category').value,
    notes: $('e-notes').value,
  };
  if (data.url && !/^https?:\/\//i.test(data.url)) return toast('URL must start with http:// or https://', 'error');
  try {
    if (state.editingId) {
      const e = state.vault.entries.find(x => x.id === state.editingId);
      Object.assign(e, data, { updated_at: Date.now() / 1000 });
      auditPush('EDIT', `Updated entry: ${title}`);
    } else {
      state.vault.entries.push({ id: crypto.randomUUID(), ...data, created_at: Date.now() / 1000, updated_at: Date.now() / 1000 });
      auditPush('ADD', `Added entry: ${title}`);
    }
    await saveVault(state.editingId ? 'Entry updated' : 'Entry added');
    closeModal('entry-modal');
    renderVault(); updateBadges();
  } catch (e) { toast(e.error || 'Save failed', 'error'); }
}

function openDetail(id) {
  const e = state.vault.entries.find(x => x.id === id);
  if (!e) return;
  state.editingId = id;
  $('detail-title').textContent = e.title;
  const st = ZK.scorePassword(e.password || '');
  $('detail-body').innerHTML = `
    <div class="detail-row"><span class="k">Username</span><span class="v mono">${esc(e.username || '—')}</span></div>
    <div class="detail-row"><span class="k">Password</span><span class="v"><span class="mono" id="dpw">••••••••</span>
      <button class="btn btn-sm btn-ghost" id="dpw-show">Show</button>
      <button class="btn btn-sm btn-ghost" id="dpw-copy">Copy</button></span></div>
    <div class="detail-row"><span class="k">Strength</span><span class="v" id="d-strength">${st.label} · ${st.entropy} bits</span></div>
    ${e.url ? `<div class="detail-row"><span class="k">URL</span><span class="v"><a href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">${esc(e.url)}</a></span></div>` : ''}
    <div class="detail-row"><span class="k">Category</span><span class="v">${esc(e.category || 'General')}</span></div>
    ${e.notes ? `<div class="detail-row"><span class="k">Notes</span><span class="v">${esc(e.notes)}</span></div>` : ''}
    <div class="detail-row"><span class="k">Updated</span><span class="v">${fmtDate(e.updated_at || e.created_at || 0)}</span></div>`;
  openModal('detail-modal');
  $('d-strength').style.color = st.color;
  let shown = false;
  $('dpw-show').onclick = () => { shown = !shown; $('dpw').textContent = shown ? (e.password || '') : '••••••••'; $('dpw-show').textContent = shown ? 'Hide' : 'Show'; };
  $('dpw-copy').onclick = () => copy(e.password || '');
}

async function deleteEntry(id) {
  const e = state.vault.entries.find(x => x.id === id);
  if (!e) return;
  state.vault.entries = state.vault.entries.filter(x => x.id !== id);
  auditPush('DELETE', `Deleted entry: ${e.title}`);
  try { await saveVault('Entry deleted'); closeModal('detail-modal'); renderVault(); updateBadges(); }
  catch (err) { toast('Delete failed', 'error'); }
}

function copy(text) { navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard', 'success')).catch(() => toast('Copy failed', 'error')); }

// ── Live strength meter (client-side) ──────────────────────────────────────
function liveStrength(pwd, barId, lblId) {
  const r = ZK.scorePassword(pwd);
  $(barId).style.width = r.score + '%';
  $(barId).style.background = r.color;
  const lbl = $(lblId);
  lbl.textContent = pwd ? `${r.label} · ${r.entropy} bits · ${r.crack_time}` : '';
  lbl.style.color = r.color;
}

// ════════════════════════════════════════════════════════════════════════════
//  ALERTS
// ════════════════════════════════════════════════════════════════════════════
function alertId(ev) { return `${ev.event_type}:${ev.ts}`; }
function computeAlerts() {
  // Events of medium+ severity become alerts; session-risk reasons are alerts too.
  const out = [];
  state.events.forEach(e => {
    const sev = sevOf(e.event_type);
    if (sevRank[sev] >= sevRank.medium) {
      const id = alertId(e);
      out.push({ id, sev, title: e.event_type, detail: e.detail, time: e.ts, status: state.vault.alerts[id] || 'open' });
    }
  });
  state.sessionRisk.reasons.forEach((r, i) => {
    const id = `RISK:${r}`;
    out.push({ id, sev: 'medium', title: 'SESSION_RISK', detail: r, time: Date.now() / 1000, status: state.vault.alerts[id] || 'open' });
  });
  return out.sort((a, b) => (sevRank[b.sev] - sevRank[a.sev]) || (b.time - a.time));
}

function renderAlerts() {
  const q = ($('alert-search').value || '').toLowerCase();
  const statusF = $('alert-status-filter').value;
  let list = computeAlerts().filter(a =>
    (state.alertSev === 'all' || a.sev === state.alertSev) &&
    (statusF === 'all' || a.status === statusF) &&
    (!q || (a.title + ' ' + a.detail).toLowerCase().includes(q)));
  const body = $('alerts-body');
  if (!list.length) { body.innerHTML = ''; $('alerts-empty').innerHTML = emptyState('No matching alerts', 'Your environment looks clean.'); return; }
  $('alerts-empty').innerHTML = '';
  body.innerHTML = list.map(a => `
    <tr>
      <td><span class="badge ${a.sev}"><span class="badge-dot"></span>${a.sev.toUpperCase()}</span></td>
      <td><strong>${esc(a.title)}</strong></td>
      <td class="muted">${esc(a.detail)}</td>
      <td class="nowrap muted">${timeAgo(a.time)}</td>
      <td><span class="badge ${a.status}">${a.status === 'progress' ? 'In progress' : a.status[0].toUpperCase() + a.status.slice(1)}</span></td>
      <td>
        <select class="select-sm" data-alert-status="${esc(a.id)}">
          <option value="open" ${a.status === 'open' ? 'selected' : ''}>Open</option>
          <option value="progress" ${a.status === 'progress' ? 'selected' : ''}>In progress</option>
          <option value="resolved" ${a.status === 'resolved' ? 'selected' : ''}>Resolved</option>
        </select>
      </td>
    </tr>`).join('');
}

async function setAlertStatus(id, status) {
  state.vault.alerts[id] = status;
  try { await saveVault(); renderAlerts(); updateBadges(); toast('Alert updated', 'success'); }
  catch { toast('Could not save alert state', 'error'); }
}

// ════════════════════════════════════════════════════════════════════════════
//  MONITORING
// ════════════════════════════════════════════════════════════════════════════
function renderMonitoring() {
  // build type filter once per render
  const types = ['all', ...new Set(state.events.map(e => e.event_type))];
  const cur = $('mon-type-filter').value || 'all';
  $('mon-type-filter').innerHTML = types.map(t => `<option value="${esc(t)}" ${t === cur ? 'selected' : ''}>${t === 'all' ? 'All event types' : esc(t)}</option>`).join('');
  const q = ($('mon-search').value || '').toLowerCase();
  const list = state.events.filter(e =>
    (cur === 'all' || e.event_type === cur) &&
    (!q || (e.event_type + ' ' + e.detail).toLowerCase().includes(q)));
  $('mon-body').innerHTML = list.length ? list.map(e => `
    <tr>
      <td><span class="badge ${sevOf(e.event_type)}">${esc(e.event_type)}</span></td>
      <td>${esc(e.detail)}</td>
      <td class="mono muted">${esc(e.ip_hash || '—')}</td>
      <td>${e.risk_score || 0}</td>
      <td class="nowrap muted">${fmtDate(e.ts)}</td>
    </tr>`).join('') : `<tr><td colspan="5">${emptyState('No events')}</td></tr>`;

  $('last-logins').innerHTML = state.lastLogins.length ? state.lastLogins.map(l => `
    <div class="feed-item">
      <span class="feed-dot dot-ok"></span>
      <div class="feed-main"><div class="t">Successful login</div><div class="d mono">${esc(l.ip_hash || '—')}</div></div>
      <span class="feed-time">${timeAgo(l.ts)}</span>
    </div>`).join('') : emptyState('No recent logins');
}

async function runAnomaly() {
  const el = $('ai-anomaly-result');
  el.style.display = 'block'; el.className = 'auth-msg info'; el.textContent = 'Analyzing…';
  try {
    const now = new Date();
    const res = await api('POST', '/ai/anomaly', { hour: now.getHours(), dow: now.getDay(), country: 'XX', ua_hash: 0 });
    if (res.is_anomaly) { el.className = 'auth-msg error'; el.textContent = `⚠ Anomaly detected (score ${res.score ?? '?'}). ${res.reason || ''}`; }
    else { el.className = 'auth-msg success'; el.textContent = `✓ Session looks normal. ${res.reason || res.detail || ''}`; }
  } catch (e) { el.className = 'auth-msg error'; el.textContent = e.error || 'Analysis unavailable'; }
}

// ════════════════════════════════════════════════════════════════════════════
//  GENERATOR
// ════════════════════════════════════════════════════════════════════════════
function genOpts() {
  return {
    length: parseInt($('gen-length').value, 10),
    uppercase: $('gen-upper').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
  };
}
async function generate() {
  let pwd = '';
  try {
    if (state.genTab === 'random') {
      pwd = ZK.generatePassword(genOpts());
    } else if (state.genTab === 'memorable') {
      const res = await api('POST', '/generate/memorable', { site: $('gen-site').value, words: 4 }, false);
      pwd = res.password;
    } else {
      const res = await api('POST', '/ai/suggest', { site: $('gen-site').value, words: 4 }, false);
      pwd = res.password;
    }
  } catch { pwd = ZK.generatePassword(genOpts()); }
  $('gen-out').textContent = pwd || '—';
  liveStrength(pwd, 'gen-strength-bar', 'gen-strength-label');
}
function switchGenTab(tab) {
  state.genTab = tab;
  document.querySelectorAll('.tab-btn[data-gen]').forEach(b => b.classList.toggle('active', b.dataset.gen === tab));
  $('gen-random-opts').classList.toggle('hidden', tab !== 'random');
  $('gen-context-opts').classList.toggle('hidden', tab === 'random');
}

// ── HIBP (client-side k-anonymity — password never leaves the device) ─────────
async function hibpCheck() {
  const pwd = $('hibp-input').value;
  const el = $('hibp-result');
  if (!pwd) return;
  el.style.display = 'block'; el.className = 'auth-msg info'; el.textContent = 'Checking…';
  try {
    const [prefix, suffix] = await ZK.sha1Prefix(pwd);
    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
    const text = await r.text();
    let count = 0;
    text.split('\n').forEach(line => { const [s, c] = line.trim().split(':'); if (s === suffix) count = parseInt(c, 10); });
    if (count > 0) { el.className = 'auth-msg error'; el.textContent = `⚠ Found in ${count.toLocaleString()} breaches — do not use this password.`; }
    else { el.className = 'auth-msg success'; el.textContent = '✓ Not found in any known breach.'; }
  } catch { el.className = 'auth-msg error'; el.textContent = 'Breach service unavailable.'; }
}

// ── Misc UI helpers ──────────────────────────────────────────────────────────
function openModal(id) { $(id).classList.add('open'); }
function closeModal(id) { $(id).classList.remove('open'); }
function togglePw(inputId, btn) {
  const input = $(inputId); if (!input) return;
  const isPw = input.type === 'password';
  input.type = isPw ? 'text' : 'password';
  const open = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const closed = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  btn.innerHTML = isPw ? closed : open;
}
function setEyes() { document.querySelectorAll('.eye').forEach(b => { if (!b.innerHTML.trim()) b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'; }); }

// ════════════════════════════════════════════════════════════════════════════
//  EVENT WIRING
// ════════════════════════════════════════════════════════════════════════════
function init() {
  // Check for WebCrypto availability
  if (!window.crypto || !window.crypto.subtle) {
    const msg = 'WebCrypto API not available. SecureVault requires a secure context (HTTPS) or localhost with a modern browser.';
    $('auth-screen').innerHTML = `
      <div class="auth-card">
        <div class="brand">
          <div class="brand-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div><h1>SecureVault</h1><div class="sub">Error</div></div>
        </div>
        <p style="color: #ef4444; margin-top: 20px;">${msg}</p>
        <p class="muted" style="margin-top: 10px;">Ensure you are using:</p>
        <ul style="margin-left: 20px; margin-top: 10px; color: #64748b;">
          <li>HTTPS in production</li>
          <li>http://localhost:5000 in development</li>
          <li>A modern browser (Chrome, Firefox, Safari, Edge)</li>
        </ul>
      </div>
    `;
    return;
  }

  applyTheme(localStorage.getItem('theme') || 'dark');
  setEyes();

  // Auth
  document.querySelectorAll('.tab-btn[data-tab]').forEach(b => b.onclick = () => switchAuthTab(b.dataset.tab));
  $('form-login').addEventListener('submit', doLogin);
  $('form-register').addEventListener('submit', doRegister);
  $('reg-pw').addEventListener('input', e => liveStrength(e.target.value, 'reg-strength-bar', 'reg-strength-label'));

  // Global delegation
  document.body.addEventListener('click', e => {
    const t = e.target.closest('[data-toggle],[data-close],[data-page],[data-cat],[data-gen],[data-sev],[data-entry]');
    if (!t) return;
    if (t.dataset.toggle) togglePw(t.dataset.toggle, t);
    else if (t.dataset.close) closeModal(t.dataset.close);
    else if (t.dataset.page) navTo(t.dataset.page);
    else if (t.dataset.cat) { state.catFilter = t.dataset.cat; renderVault(); }
    else if (t.dataset.gen) switchGenTab(t.dataset.gen);
    else if (t.dataset.sev) { state.alertSev = t.dataset.sev; document.querySelectorAll('[data-sev]').forEach(c => c.classList.toggle('active', c === t)); renderAlerts(); }
    else if (t.dataset.entry) openDetail(t.dataset.entry);
  });
  document.body.addEventListener('change', e => {
    if (e.target.dataset.alertStatus) setAlertStatus(e.target.dataset.alertStatus, e.target.value);
  });

  // Top bar
  $('theme-toggle').onclick = toggleTheme;
  $('logout-btn').onclick = doLogout;
  $('hamburger').onclick = () => $('sidebar').classList.toggle('open');

  // Vault
  $('add-entry-btn').onclick = () => openEntryModal(null);
  $('vault-search').addEventListener('input', e => { state.vaultQuery = e.target.value; renderVault(); });
  $('entry-save-btn').onclick = saveEntry;
  $('e-password').addEventListener('input', e => liveStrength(e.target.value, 'e-strength-bar', 'e-strength-label'));
  $('e-gen-btn').onclick = () => { const p = ZK.generatePassword({ length: 20 }); $('e-password').value = p; liveStrength(p, 'e-strength-bar', 'e-strength-label'); };
  $('detail-edit').onclick = () => { closeModal('detail-modal'); openEntryModal(state.editingId); };
  $('detail-delete').onclick = () => { if (confirm('Delete this entry permanently?')) deleteEntry(state.editingId); };

  // Generator
  $('gen-length').addEventListener('input', e => $('gen-length-val').textContent = e.target.value);
  $('gen-generate').onclick = generate;
  $('gen-refresh').onclick = generate;
  $('gen-copy').onclick = () => copy($('gen-out').textContent);
  $('hibp-btn').onclick = hibpCheck;

  // Alerts / monitoring filters
  $('alert-search').addEventListener('input', renderAlerts);
  $('alert-status-filter').addEventListener('change', renderAlerts);
  $('mon-search').addEventListener('input', renderMonitoring);
  $('mon-type-filter').addEventListener('change', renderMonitoring);
  $('ai-anomaly-btn').onclick = runAnomaly;

  // Periodic SOC refresh (poll — CSP-clean, no socket.io client dependency)
  setInterval(() => { if (state.token) refreshAll(); }, 20000);
}

document.addEventListener('DOMContentLoaded', init);
