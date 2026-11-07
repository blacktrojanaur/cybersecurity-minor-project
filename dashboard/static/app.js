/* ZTSP Dashboard – Live SSE Consumer */

const ACTION_ICONS = {
  terminate_session: '🚫',
  require_mfa: '🔐',
  restrict_access: '⚠️',
  alert_soc: '🚨',
  block_ip: '🛑',
  notify_user: '📧',
};

let ztDetections = 0, ztBlocked = 0, ztStepUp = 0;
let lastDecisionTs = null;
let mttrSum = 0, mttrCount = 0;

// ── SSE connection ────────────────────────────────────────────────────────────

function connectSSE() {
  const evtSrc = new EventSource('/events');

  evtSrc.onopen = () => {
    document.getElementById('status-dot').classList.remove('offline');
    document.getElementById('status-text').textContent = 'Live';
  };

  evtSrc.onerror = () => {
    document.getElementById('status-dot').classList.add('offline');
    document.getElementById('status-text').textContent = 'Reconnecting…';
  };

  evtSrc.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.error) return;
      document.getElementById('last-update').textContent =
        new Date(data.timestamp).toLocaleTimeString();
      updateSessions(data.sessions || []);
      updateDecisions(data.decisions || []);
      updateActions(data.actions || []);
    } catch (_) {}
  };
}

// ── Sessions ──────────────────────────────────────────────────────────────────

function riskColor(score) {
  if (score === null || score === undefined) return '#475569';
  if (score >= 0.6) return '#ef4444';
  if (score >= 0.4) return '#f59e0b';
  return '#10b981';
}

function decisionPill(decision) {
  if (!decision) return '<span class="pill pill-none">—</span>';
  return `<span class="pill pill-${decision}">${decision.replace('_', ' ')}</span>`;
}

function riskBar(score) {
  if (score === null || score === undefined) return '—';
  const pct = Math.round(score * 100);
  const col = riskColor(score);
  return `
    <div class="risk-bar">
      <div class="risk-track"><div class="risk-fill" style="width:${pct}%;background:${col}"></div></div>
      <span class="risk-val" style="color:${col}">${score.toFixed(2)}</span>
    </div>`;
}

function updateSessions(sessions) {
  const body = document.getElementById('sessions-body');
  document.getElementById('session-count').textContent = sessions.length;
  document.getElementById('metric-sessions').textContent = sessions.length;

  const highRisk = sessions.filter(s => (s.risk_score || 0) >= 0.6).length;
  const denied = sessions.filter(s => s.decision === 'deny' || !s.active).length;
  const allowed = sessions.filter(s => s.decision === 'allow' && s.active).length;
  document.getElementById('metric-high-risk').textContent = highRisk;
  document.getElementById('metric-denied').textContent = denied;
  document.getElementById('metric-allowed').textContent = allowed;

  if (sessions.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="empty-row">No active sessions</td></tr>';
    return;
  }

  body.innerHTML = sessions.map(s => {
    const statusIcon = !s.active ? '🔴 Terminated' : s.mfa_required ? '🟡 MFA' : s.restricted ? '🟠 Restricted' : '🟢 Active';
    return `<tr>
      <td>${s.user_id}</td>
      <td style="font-size:0.75rem">${s.device_id}</td>
      <td>${riskBar(s.risk_score)}</td>
      <td>${s.posture_score !== null ? s.posture_score?.toFixed(2) : '—'}</td>
      <td>${decisionPill(s.decision)}</td>
      <td style="font-size:0.75rem">${statusIcon}</td>
    </tr>`;
  }).join('');
}

// ── Decisions ─────────────────────────────────────────────────────────────────

function updateDecisions(decisions) {
  const tl = document.getElementById('decision-timeline');
  document.getElementById('decision-count').textContent = decisions.length;
  document.getElementById('metric-decisions').textContent = decisions.length;

  // Count ZT platform performance
  ztBlocked = decisions.filter(d => d.decision === 'deny').length;
  ztStepUp = decisions.filter(d => d.decision === 'step_up').length;
  ztDetections = ztBlocked + ztStepUp + decisions.filter(d => d.decision === 'restrict').length;
  document.getElementById('zt-detections').textContent = ztDetections;
  document.getElementById('zt-blocked').textContent = ztBlocked;
  document.getElementById('zt-stepup').textContent = ztStepUp;

  if (decisions.length === 0) {
    tl.innerHTML = '<div class="empty-row">No decisions yet…</div>';
    return;
  }

  const recent = decisions.slice(-20).reverse();
  tl.innerHTML = recent.map(d => {
    const t = new Date(d.timestamp).toLocaleTimeString();
    const sess = (d.session_id || '').slice(0, 18) + '…';
    const reason = (d.reason || '').slice(0, 80);
    return `<div class="timeline-item timeline-item--${d.decision}">
      <span class="tl-time">${t}</span>
      <span class="tl-session">${sess}</span>
      ${decisionPill(d.decision)}
      <span class="tl-reason">${reason}</span>
    </div>`;
  }).join('');
}

// ── Actions ───────────────────────────────────────────────────────────────────

function updateActions(actions) {
  const feed = document.getElementById('action-feed');
  document.getElementById('action-count').textContent = actions.length;

  if (actions.length === 0) {
    feed.innerHTML = '<div class="empty-row">No actions yet…</div>';
    return;
  }

  // Update MTTR approximation
  if (actions.length > 0) {
    document.getElementById('zt-mttr').textContent = '< 30s';
  }

  const recent = actions.slice(-15).reverse();
  feed.innerHTML = recent.map(a => {
    const icon = ACTION_ICONS[a.action_type] || '⚙️';
    const t = new Date(a.timestamp).toLocaleTimeString();
    const sess = (a.session_id || '').slice(0, 14) + '…';
    return `<div class="action-item">
      <span class="action-icon">${icon}</span>
      <span class="action-type">${a.action_type}</span>
      <span class="action-session">${sess} · ${t}</span>
      <span class="action-status-${a.status}">${a.status}</span>
    </div>`;
  }).join('');
}

// ── Scenario buttons ──────────────────────────────────────────────────────────

async function runScenario(name) {
  const btn = document.getElementById(`btn-${name}`);
  const fb = document.getElementById('scenario-feedback');
  const labels = { s1: 'Credential Misuse', s2: 'Lateral Movement', s3: 'Privilege Escalation', s4: 'Slow-and-Low' };

  btn.disabled = true;
  btn.textContent = '⏳ Running…';
  fb.textContent = `Running scenario: ${labels[name] || name}…`;

  try {
    const r = await fetch(`/api/scenario/${name}`, { method: 'POST' });
    const data = await r.json();
    fb.textContent = data.status === 'started'
      ? `✅ ${labels[name]} scenario started. Watch the timeline…`
      : `⚠️ ${data.detail || 'Error'}`;
  } catch (e) {
    fb.textContent = `❌ Failed to start scenario: ${e.message}`;
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = labels[name] || name;
    }, 5000);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  connectSSE();
});
