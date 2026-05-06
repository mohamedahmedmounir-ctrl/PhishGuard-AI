/**
 * PhishGuard AI — Frontend Script
 * ================================
 * Handles: tab navigation, form submission, API calls,
 * result rendering, gauge animation, history table, stats update.
 */

"use strict";

/* ── Tab Navigation ────────────────────────────────── */
document.querySelectorAll('.nav-pill').forEach(pill => {
  pill.addEventListener('click', () => {
    const tab = pill.dataset.tab;
    document.querySelectorAll('.nav-pill').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => { t.classList.add('hidden'); t.classList.remove('active'); });
    pill.classList.add('active');
    const el = document.getElementById(`tab-${tab}`);
    if (el) { el.classList.remove('hidden'); el.classList.add('active'); }
    if (tab === 'history') loadHistory();
  });
});

/* ── Email character counter ───────────────────────── */
const emailInput = document.getElementById('emailInput');
const emailMeta  = document.getElementById('emailMeta');
emailInput.addEventListener('input', () => {
  emailMeta.textContent = `${emailInput.value.length.toLocaleString()} / 10,000 characters`;
});

/* ── Fill URL example ──────────────────────────────── */
function fillUrl(url) {
  document.getElementById('urlInput').value = url;
}

/* ═══ SCAN EMAIL ═══════════════════════════════════════ */
async function scanEmail() {
  const text = emailInput.value.trim();
  if (!text) { showToast('Please paste email text first.', true); return; }
  if (text.length < 10) { showToast('Email text is too short.', true); return; }

  showLoading('ANALYZING EMAIL…');
  try {
    const res  = await fetch('/analyze/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    if (!res.ok) { throw new Error(data.error || 'Analysis failed'); }
    renderEmailResult(data);
    refreshStats();
  } catch (err) {
    showToast('Error: ' + err.message, true);
  } finally {
    hideLoading();
  }
}

/* ═══ SCAN URL ═════════════════════════════════════════ */
async function scanUrl() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { showToast('Please enter a URL first.', true); return; }

  showLoading('SCANNING URL…');
  try {
    const res  = await fetch('/analyze/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!res.ok) { throw new Error(data.error || 'Analysis failed'); }
    renderUrlResult(data);
    refreshStats();
  } catch (err) {
    showToast('Error: ' + err.message, true);
  } finally {
    hideLoading();
  }
}

/* ── Render Email Result ───────────────────────────── */
function renderEmailResult(data) {
  const panel    = document.getElementById('resultPanel');
  const verdict  = data.verdict;      // "phishing" | "legitimate"
  const risk     = data.risk_score;
  const mlConf   = data.ml_confidence;

  // Show panel
  panel.classList.remove('hidden');
  panel.className = `result-panel border-${verdict}`;

  // Icon + verdict
  document.getElementById('resultIcon').textContent    = verdict === 'phishing' ? '⚠' : '✓';
  document.getElementById('resultIcon').style.color    = verdict === 'phishing' ? 'var(--accent-red)' : 'var(--accent-green)';
  const vEl = document.getElementById('resultVerdict');
  vEl.textContent = verdict.toUpperCase();
  vEl.className   = `result-verdict verdict-${verdict}`;
  document.getElementById('resultType').textContent    = '✉ EMAIL SCAN';

  // Scores
  document.getElementById('riskScore').textContent   = `${risk}%`;
  document.getElementById('threatLevel').textContent = data.threat_level;
  document.getElementById('mlConf').textContent      = `${mlConf}%`;
  document.getElementById('mlConfBlock').classList.remove('hidden');

  // Gauge
  animateGauge(risk, verdict);

  // Recommendation
  const rec = document.getElementById('recommendation');
  rec.textContent = data.recommendation;
  rec.className   = `recommendation rec-${verdict}`;

  // Keyword tags
  const tags = document.getElementById('keywordTags');
  tags.innerHTML = '';
  const kws = data.features?.keyword_matches || [];
  if (kws.length) {
    kws.forEach(kw => {
      const span = document.createElement('span');
      span.className = 'keyword-tag';
      span.textContent = kw;
      tags.appendChild(span);
    });
  } else {
    tags.innerHTML = '<span style="color:var(--accent-green);font-family:var(--font-mono);font-size:0.8rem">No phishing keywords detected</span>';
  }

  // Highlighted text
  document.getElementById('highlightedText').innerHTML = data.highlighted || '';
  document.getElementById('emailDetails').classList.remove('hidden');
  document.getElementById('urlDetails').classList.add('hidden');

  // Scroll to result
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ── Render URL Result ─────────────────────────────── */
function renderUrlResult(data) {
  const panel   = document.getElementById('resultPanel');
  const verdict = data.verdict;   // "phishing" | "suspicious" | "safe"
  const risk    = data.risk_score;

  panel.classList.remove('hidden');
  panel.className = `result-panel border-${verdict}`;

  document.getElementById('resultIcon').textContent  = verdict === 'phishing' ? '⚠' : verdict === 'suspicious' ? '⬡' : '✓';
  document.getElementById('resultIcon').style.color  = verdictColor(verdict);
  const vEl = document.getElementById('resultVerdict');
  vEl.textContent = verdict.toUpperCase();
  vEl.className   = `result-verdict verdict-${verdict}`;
  document.getElementById('resultType').textContent  = '⛓ URL SCAN';

  document.getElementById('riskScore').textContent   = `${risk}%`;
  document.getElementById('threatLevel').textContent = data.threat_level;
  document.getElementById('mlConfBlock').classList.add('hidden');

  animateGauge(risk, verdict);

  const rec = document.getElementById('recommendation');
  rec.textContent = data.recommendation;
  rec.className   = `recommendation rec-${verdict}`;

  // Findings
  const findingsEl = document.getElementById('urlFindings');
  findingsEl.innerHTML = '';
  const findings = data.findings || [];
  if (findings.length) {
    findings.forEach(f => {
      const div = document.createElement('div');
      div.className = 'finding-item';
      div.textContent = f;
      findingsEl.appendChild(div);
    });
  } else {
    const div = document.createElement('div');
    div.className = 'finding-item safe';
    div.textContent = '✅ No suspicious indicators detected.';
    findingsEl.appendChild(div);
  }

  // Feature checklist
  const checklist = document.getElementById('urlChecklist');
  checklist.innerHTML = '';
  const summary = data.feature_summary || [];
  if (summary.length) {
    checklist.classList.remove('hidden');
    summary.forEach(item => {
      const d = document.createElement('div');
      d.className = 'check-item';
      d.innerHTML = `<span class="check-label">${item.label}</span><span class="check-val ${item.safe ? 'good' : 'bad'}">${item.value}</span>`;
      checklist.appendChild(d);
    });
  }

  document.getElementById('urlDetails').classList.remove('hidden');
  document.getElementById('emailDetails').classList.add('hidden');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ── Risk Gauge Animation ──────────────────────────── */
function animateGauge(riskPct, verdict) {
  const arc   = document.getElementById('gaugeFill');
  const label = document.getElementById('gaugeText');
  const total = 251.2;
  const offset = total - (riskPct / 100) * total;
  const color = verdictColor(verdict);

  arc.style.stroke = color;
  arc.style.filter = `drop-shadow(0 0 6px ${color})`;
  label.style.fill = color;

  // Animate dashoffset
  let current = total;
  const target = offset;
  const step = (total - target) / 40;
  let count = 0;
  const timer = setInterval(() => {
    current -= step;
    if (current <= target || count > 50) {
      current = target;
      clearInterval(timer);
    }
    arc.style.strokeDashoffset = current;
    const displayed = Math.round(((total - current) / total) * 100);
    label.textContent = `${displayed}%`;
    count++;
  }, 16);
}

function verdictColor(verdict) {
  if (verdict === 'phishing')   return 'var(--accent-red)';
  if (verdict === 'suspicious') return 'var(--accent-orange)';
  return 'var(--accent-green)';
}

/* ═══ HISTORY TABLE ════════════════════════════════════ */
async function loadHistory() {
  try {
    const res  = await fetch('/logs');
    const logs = await res.json();
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = '';

    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No scans yet.</td></tr>';
      return;
    }

    logs.forEach(log => {
      const tr = document.createElement('tr');
      const ts = new Date(log.timestamp).toLocaleString();
      tr.innerHTML = `
        <td style="color:var(--text-dim)">${log.id}</td>
        <td><span style="font-family:var(--font-head);font-size:0.6rem;letter-spacing:0.1em;color:var(--accent-blue)">${(log.type || 'email').toUpperCase()}</span></td>
        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(log.input)}">${escHtml(log.input)}</td>
        <td><span class="verdict-pill ${log.verdict}">${log.verdict?.toUpperCase()}</span></td>
        <td>${riskBar(log.risk_score)}</td>
        <td><span class="threat-badge threat-${log.threat_level}">${log.threat_level}</span></td>
        <td style="color:var(--text-dim);font-size:0.7rem">${ts}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    showToast('Failed to load history.', true);
  }
}

function riskBar(score) {
  const color = score >= 70 ? 'var(--accent-red)'
              : score >= 40 ? 'var(--accent-orange)'
              : 'var(--accent-green)';
  return `<div style="display:flex;align-items:center;gap:0.5rem">
    <div style="width:60px;height:4px;background:rgba(255,255,255,0.05);border-radius:2px;overflow:hidden">
      <div style="width:${score}%;height:100%;background:${color}"></div>
    </div>
    <span style="color:${color};font-size:0.75rem">${score}%</span>
  </div>`;
}

/* ═══ STATS ════════════════════════════════════════════ */
async function refreshStats() {
  try {
    const res   = await fetch('/stats');
    const stats = await res.json();
    const total = stats.total_scans || 0;

    document.getElementById('totalScans').textContent = total;
    document.getElementById('threatCount').textContent = stats.phishing_count || 0;
    document.getElementById('cleanCount').textContent  = stats.legitimate_count || 0;
    document.getElementById('avgRisk').textContent     = `${stats.avg_risk_score || 0}%`;

    if (total > 0) {
      document.getElementById('threatBar').style.width = `${(stats.phishing_count / total * 100).toFixed(0)}%`;
      document.getElementById('cleanBar').style.width  = `${(stats.legitimate_count / total * 100).toFixed(0)}%`;
      document.getElementById('avgRiskBar').style.width = `${stats.avg_risk_score || 0}%`;
    }
  } catch (_) { /* silently ignore stats fetch failures */ }
}

/* ═══ EXPORT ═══════════════════════════════════════════ */
function exportLogs() {
  window.open('/export', '_blank');
}

/* ── Loading helpers ───────────────────────────────── */
function showLoading(msg = 'ANALYZING…') {
  document.getElementById('loadingText').textContent = msg;
  document.getElementById('loadingOverlay').classList.remove('hidden');
}
function hideLoading() {
  document.getElementById('loadingOverlay').classList.add('hidden');
}

/* ── Toast ─────────────────────────────────────────── */
let _toastTimer;
function showToast(msg, isError = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast${isError ? ' error' : ''}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
}

/* ── Escape HTML ───────────────────────────────────── */
function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

/* ── Init ──────────────────────────────────────────── */
refreshStats();
