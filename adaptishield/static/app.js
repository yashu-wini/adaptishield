/* ══════════════════════════════════════════════════
   AdaptiShield — Dashboard Application Logic
   ══════════════════════════════════════════════════ */

// ─── State ───
const state = {
  analyses: [],          // all analysis results
  allEntities: [],       // flattened entities across runs
  allAnon: [],           // flattened anon mappings
  docsProcessed: 0,
  totalEntities: 0,
  totalRiskScore: 0,
  totalLatency: 0,
};

const SAMPLES = [
  "Hello, I am Priya Mehta. You can reach me at priya.mehta@gmail.com or +91-9876543210. My Aadhaar is 2345 6789 0123 and PAN is ABCDE1234F.",
  "Name: Priya Mehta | Aadhaar: 2345 6789 0123 | PAN: BVLPM3142K | DOB: 15/03/1988 | Phone: +91-9876543210 | Email: priya.mehta@gmail.com | Bank Account: 1234567890123",
  "User: admin@company.com | Password: Secure@123! | Credit Card: 4532015112830366 | Aadhaar: 9876 5432 1098"
];

const PIPE_STEPS = [
  { name: "Ingestion & text cleaning", icon: "ti-file-import" },
  { name: "Regex PII detection", icon: "ti-regex" },
  { name: "Transformer detection (DeBERTa)", icon: "ti-brain" },
  { name: "spaCy NER detection", icon: "ti-language" },
  { name: "Fusion engine (dedup + boost)", icon: "ti-git-merge" },
  { name: "Context validation", icon: "ti-search" },
  { name: "Confidence recalibration", icon: "ti-adjustments-alt" },
  { name: "Sensitivity & risk scoring", icon: "ti-alert-triangle" },
  { name: "Adaptive anonymization", icon: "ti-ghost" },
  { name: "AES-256-GCM encryption", icon: "ti-lock" },
];

const RISK_META = {
  LOW:      { icon: "🟢", color: "var(--green)",  sub: "Document appears safe — minor PII only" },
  MEDIUM:   { icon: "🟡", color: "var(--yellow)", sub: "PII detected — masking recommended" },
  HIGH:     { icon: "🔴", color: "var(--red)",    sub: "Sensitive PII found — redaction recommended" },
  CRITICAL: { icon: "🚨", color: "var(--red)",    sub: "Critical data exposure — immediate action required" },
};

// ─── Navigation ───
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const page = item.dataset.page;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById('page-' + page).classList.add('active');
  });
});

// ─── Health check ───
async function checkHealth() {
  const badge = document.getElementById('healthBadge');
  try {
    const r = await fetch('/health');
    if (r.ok) { badge.innerHTML = '<i class="ti ti-heart-rate-monitor"></i> Online'; badge.classList.add('online'); }
    else { badge.innerHTML = '<i class="ti ti-alert-circle"></i> Error'; badge.classList.remove('online'); }
  } catch { badge.innerHTML = '<i class="ti ti-wifi-off"></i> Offline'; badge.classList.remove('online'); }
}
checkHealth();

// ─── Char count ───
const textInput = document.getElementById('textInput');
const charCount = document.getElementById('charCount');
textInput.addEventListener('input', () => { charCount.textContent = textInput.value.length; });

// ─── Load sample ───
function loadSample(idx) {
  textInput.value = SAMPLES[idx];
  charCount.textContent = SAMPLES[idx].length;
}

// ─── Analyze ───
document.getElementById('analyzeBtn').addEventListener('click', runAnalysis);

async function runAnalysis() {
  const text = textInput.value.trim();
  if (!text) return;

  const btn = document.getElementById('analyzeBtn');
  btn.disabled = true;
  btn.innerHTML = '<i class="ti ti-loader" style="animation:spin 1s linear infinite"></i> Running pipeline...';

  try {
    const res = await fetch('/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, document_name: 'web_input_' + Date.now() + '.txt' })
    });
    const data = await res.json();
    handleResult(data, text);
  } catch (e) {
    console.error(e);
    addAudit('Pipeline request failed: ' + e.message, 'Network error', 'err');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-bolt"></i> Run pipeline';
  }
}

function handleResult(data, originalText) {
  state.docsProcessed++;
  state.totalEntities += data.entities.length;
  state.totalRiskScore += (data.risk_analysis.risk_score || 0);
  state.totalLatency += (data.processing_time_ms || 0);
  state.analyses.unshift(data);
  data.entities.forEach(e => state.allEntities.push(e));
  data.entities.forEach(e => state.allAnon.push(e));

  // Show results
  document.getElementById('resultsArea').style.display = 'flex';
  document.getElementById('resultsArea').style.flexDirection = 'column';
  document.getElementById('resultsArea').style.gap = '16px';

  renderRiskBanner(data);
  renderPipeline(data);
  renderEntities(data);
  renderAnon(data);
  renderTextDiff(originalText, data);
  renderRecommendations(data);
  renderEncryption(data);
  updateOverview();
  updateEntityExplorer();
  updateAnonExplorer();

  const rl = data.risk_analysis.risk_level;
  const status = rl === 'CRITICAL' ? 'err' : (rl === 'HIGH' ? 'warn' : 'ok');
  addAudit(
    `${data.document_name} processed — ${data.entities.length} entities, risk ${rl}`,
    `doc_id: ${data.document_id} · score: ${data.risk_analysis.risk_score} · ${data.processing_time_ms}ms · encrypted: ${data.encrypted ? 'yes' : 'no'}`,
    status
  );
}

// ─── Render: Risk banner ───
function renderRiskBanner(data) {
  const risk = data.risk_analysis;
  const meta = RISK_META[risk.risk_level] || RISK_META.LOW;
  const banner = document.getElementById('riskBanner');
  banner.className = 'risk-banner risk-' + risk.risk_level + ' fade-in';
  document.getElementById('riskIcon').textContent = meta.icon;
  document.getElementById('riskLevel').textContent = risk.risk_level;
  document.getElementById('riskLevel').style.color = meta.color;
  document.getElementById('riskSub').textContent = meta.sub;
  document.getElementById('rsScore').textContent = (risk.risk_score || 0).toFixed(1);
  document.getElementById('rsEntities').textContent = risk.entity_count;
  document.getElementById('rsTime').textContent = (data.processing_time_ms || 0).toFixed(0) + 'ms';
  document.getElementById('rsEncrypt').textContent = data.encrypted ? '✓ AES-256' : 'No';
}

// ─── Render: Pipeline ───
function renderPipeline(data) {
  const el = document.getElementById('pipelineSteps');
  el.innerHTML = PIPE_STEPS.map(s =>
    `<div class="pipe-step done fade-in"><i class="ti ${s.icon}" style="font-size:14px"></i><span class="pipe-name">${s.name}</span><span class="pipe-badge badge-done">done</span></div>`
  ).join('');

  const ds = data.detection_stats || {};
  document.getElementById('detectionStats').innerHTML = `
    <div class="det-stat"><strong>${ds.regex || 0}</strong> regex</div>
    <div class="det-stat"><strong>${ds.transformer || 0}</strong> transformer</div>
    <div class="det-stat"><strong>${ds.spacy || 0}</strong> spaCy</div>
    <div class="det-stat"><strong>${ds.fused || 0}</strong> fused</div>
    <div class="det-stat"><strong>${ds.after_context_validation || 0}</strong> after context</div>
  `;
  document.getElementById('pipeHint').textContent = (data.processing_time_ms || 0).toFixed(0) + 'ms total';
}

// ─── Render: Entities ───
function renderEntities(data) {
  const el = document.getElementById('entityTable');
  document.getElementById('entityCountHint').textContent = data.entities.length + ' found';
  if (!data.entities.length) { el.innerHTML = '<div class="empty-state"><i class="ti ti-mood-happy"></i><span>No PII detected!</span></div>'; return; }
  el.innerHTML = data.entities.map(e => {
    const cls = etClass(e.sensitivity_level);
    const confPct = ((e.confidence || 0) * 100).toFixed(0);
    const confColor = confPct > 85 ? 'var(--green)' : confPct > 60 ? 'var(--yellow)' : 'var(--red)';
    return `<div class="ent-row fade-in">
      <span class="ent-type ${cls}">${e.entity_type}</span>
      <span class="ent-val" title="${esc(e.original_value)}">${esc(e.original_value)}</span>
      <div class="conf-bar"><div class="conf-fill" style="width:${confPct}%;background:${confColor}"></div></div>
      <span class="ent-conf">${confPct}%</span>
      <span class="ent-action">${e.strategy || ''}</span>
    </div>`;
  }).join('');
}

// ─── Render: Anonymization ───
function renderAnon(data) {
  const el = document.getElementById('anonList');
  if (!data.entities.length) { el.innerHTML = '<div class="empty-state"><i class="ti ti-check"></i><span>Nothing to anonymize.</span></div>'; return; }
  el.innerHTML = data.entities.map(e =>
    `<div class="anon-row fade-in">
      <span class="anon-orig" title="${esc(e.original_value)}">${esc(e.original_value)}</span>
      <i class="ti ti-arrow-right anon-arrow"></i>
      <span class="anon-result anon-${e.strategy || 'MASK'}" title="${esc(e.anonymized_value)}">${esc(e.anonymized_value)}</span>
      <span class="anon-strategy">${e.strategy || ''}</span>
    </div>`
  ).join('');
}

// ─── Render: Text diff ───
function renderTextDiff(originalText, data) {
  document.getElementById('origText').textContent = originalText;
  document.getElementById('anonText').textContent = data.anonymized_text || originalText;
}

// ─── Render: Recommendations ───
function renderRecommendations(data) {
  const el = document.getElementById('recommendations');
  const recs = data.risk_analysis.recommendations || [];
  if (!recs.length) { el.innerHTML = '<div class="rec-item">No specific recommendations.</div>'; return; }
  el.innerHTML = recs.map(r => `<div class="rec-item fade-in">${r}</div>`).join('');
}

// ─── Render: Encryption ───
function renderEncryption(data) {
  const card = document.getElementById('encryptionCard');
  const el = document.getElementById('encryptionInfo');
  if (!data.encrypted_payload) { card.style.display = 'none'; return; }
  card.style.display = 'block';
  const ep = data.encrypted_payload;
  el.innerHTML = `
    <div class="enc-field"><div class="enc-label">Algorithm</div><div class="enc-val">${ep.algorithm || 'AES-256-GCM'}</div></div>
    <div class="enc-field"><div class="enc-label">Key size</div><div class="enc-val">${ep.key_size || 256} bits</div></div>
    <div class="enc-field"><div class="enc-label">Nonce</div><div class="enc-val">${ep.nonce || '—'}</div></div>
    <div class="enc-field"><div class="enc-label">Ciphertext (preview)</div><div class="enc-val">${(ep.ciphertext || '').substring(0, 80)}...</div></div>
  `;
}

// ─── Update: Overview ───
function updateOverview() {
  document.getElementById('mDocsProcessed').textContent = state.docsProcessed;
  document.getElementById('mEntitiesFound').textContent = state.totalEntities;
  document.getElementById('mAvgRisk').textContent = state.docsProcessed ? (state.totalRiskScore / state.docsProcessed).toFixed(1) : '—';
  document.getElementById('mAvgLatency').textContent = state.docsProcessed ? (state.totalLatency / state.docsProcessed).toFixed(0) + 'ms' : '—';
  document.getElementById('recentCount').textContent = state.analyses.length + ' runs';

  // Recent list
  const rl = document.getElementById('recentList');
  rl.innerHTML = state.analyses.slice(0, 8).map(a => {
    const risk = a.risk_analysis.risk_level;
    const dotColor = risk === 'CRITICAL' ? 'var(--red)' : risk === 'HIGH' ? 'var(--yellow)' : risk === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)';
    return `<div class="recent-item">
      <div class="recent-risk" style="background:${dotColor}"></div>
      <span class="recent-name">${a.document_name}</span>
      <span class="recent-ents">${a.risk_analysis.entity_count} entities</span>
      <span class="recent-time">${risk}</span>
    </div>`;
  }).join('');

  // Entity breakdown chart
  const counts = {};
  state.allEntities.forEach(e => { counts[e.entity_type] = (counts[e.entity_type] || 0) + 1; });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = sorted.length ? sorted[0][1] : 1;
  const chartEl = document.getElementById('entityBreakdownChart');
  const colors = ['#6c9cff', '#a78bfa', '#4ade80', '#fbbf24', '#f87171', '#38bdf8', '#fb923c', '#e879f9'];
  chartEl.innerHTML = sorted.map(([type, count], i) =>
    `<div class="bar-row fade-in">
      <span class="bar-label">${type}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100)}%;background:${colors[i % colors.length]}">${count}</div></div>
    </div>`
  ).join('') || '<div class="empty-state"><i class="ti ti-chart-pie-off"></i><span>Run an analysis first.</span></div>';
}

// ─── Update: Entity explorer ───
function updateEntityExplorer() {
  const el = document.getElementById('allEntitiesTable');
  document.getElementById('allEntCount').textContent = state.allEntities.length + ' total';
  if (!state.allEntities.length) { el.innerHTML = '<div class="empty-state"><i class="ti ti-database-off"></i><span>No entities yet.</span></div>'; return; }
  el.innerHTML = '<div class="entity-table">' + state.allEntities.map(e => {
    const cls = etClass(e.sensitivity_level);
    const confPct = ((e.confidence || 0) * 100).toFixed(0);
    const confColor = confPct > 85 ? 'var(--green)' : confPct > 60 ? 'var(--yellow)' : 'var(--red)';
    return `<div class="ent-row">
      <span class="ent-type ${cls}">${e.entity_type}</span>
      <span class="ent-val" title="${esc(e.original_value)}">${esc(e.original_value)}</span>
      <div class="conf-bar"><div class="conf-fill" style="width:${confPct}%;background:${confColor}"></div></div>
      <span class="ent-conf">${confPct}%</span>
      <span class="ent-action">${e.strategy || ''}</span>
    </div>`;
  }).join('') + '</div>';
}

// ─── Update: Anon explorer ───
function updateAnonExplorer() {
  const el = document.getElementById('allAnonTable');
  document.getElementById('allAnonCount').textContent = state.allAnon.length + ' transformations';
  if (!state.allAnon.length) { el.innerHTML = '<div class="empty-state"><i class="ti ti-arrows-exchange"></i><span>No transformations yet.</span></div>'; return; }
  el.innerHTML = '<div class="anon-list">' + state.allAnon.map(e =>
    `<div class="anon-row">
      <span class="anon-orig" title="${esc(e.original_value)}">${esc(e.original_value)}</span>
      <i class="ti ti-arrow-right anon-arrow"></i>
      <span class="anon-result anon-${e.strategy || 'MASK'}" title="${esc(e.anonymized_value)}">${esc(e.anonymized_value)}</span>
      <span class="anon-strategy">${e.strategy || ''}</span>
    </div>`
  ).join('') + '</div>';
}

// ─── Audit ───
function addAudit(msg, meta, status) {
  const t = new Date();
  const time = t.getHours().toString().padStart(2,'0') + ':' + t.getMinutes().toString().padStart(2,'0') + ':' + t.getSeconds().toString().padStart(2,'0');
  const dotCls = status === 'err' ? 'audit-dot-err' : status === 'warn' ? 'audit-dot-warn' : 'audit-dot-ok';
  const html = `<div class="audit-item fade-in">
    <div class="audit-dot ${dotCls}"></div>
    <div class="audit-body"><div class="audit-msg">${msg}</div><div class="audit-meta">${meta}</div></div>
    <div class="audit-time">${time}</div>
  </div>`;
  ['auditList', 'fullAuditList'].forEach(id => {
    const el = document.getElementById(id);
    const empty = el.querySelector('.empty-state');
    if (empty) empty.remove();
    el.insertAdjacentHTML('afterbegin', html);
  });
}

// ─── Helpers ───
function etClass(level) {
  if (level === 'CRITICAL') return 'et-critical';
  if (level === 'HIGH') return 'et-high';
  if (level === 'MEDIUM') return 'et-med';
  return 'et-low';
}
function esc(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ─── Init audit ───
addAudit('AdaptiShield dashboard loaded', 'Pipeline initialized and ready', 'ok');
