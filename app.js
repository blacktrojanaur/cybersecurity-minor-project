/* ZTSP Dashboard – Live SSE & Interactive GitHub Pages / Vercel Demo Mode */

const ACTION_ICONS = {
  terminate_session: '🚫',
  require_mfa: '🔐',
  restrict_access: '⚠️',
  alert_soc: '🚨',
  block_ip: '🛑',
  notify_user: '📧',
};

let isDemoMode = false;
let sessions = [];
let decisions = [];
let actions = [];

let ztDetections = 0, ztBlocked = 0, ztStepUp = 0;

// ── Baseline Demo State ────────────────────────────────────────────────────────

function initDemoData() {
  const now = Date.now();
  sessions = [
    {
      session_id: 'sess-alice-base-91',
      user_id: 'alice',
      device_id: 'dev-alice-laptop',
      ip_address: '10.0.1.15',
      risk_score: 0.12,
      posture_score: 0.95,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
    },
    {
      session_id: 'sess-bob-base-42',
      user_id: 'bob',
      device_id: 'dev-bob-workstation',
      ip_address: '10.0.1.20',
      risk_score: 0.18,
      posture_score: 0.88,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
    },
    {
      session_id: 'sess-frank-base-18',
      user_id: 'frank',
      device_id: 'dev-frank-laptop',
      ip_address: '10.0.2.14',
      risk_score: 0.24,
      posture_score: 0.79,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
    },
    {
      session_id: 'sess-eve-base-65',
      user_id: 'eve',
      device_id: 'dev-eve-laptop',
      ip_address: '10.0.3.33',
      risk_score: 0.09,
      posture_score: 0.92,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
    }
  ];

  decisions = [
    {
      timestamp: new Date(now - 120000).toISOString(),
      session_id: 'sess-eve-base-65',
      decision: 'allow',
      reason: 'Low risk score (0.09) + compliant managed device posture (0.92)'
    },
    {
      timestamp: new Date(now - 240000).toISOString(),
      session_id: 'sess-frank-base-18',
      decision: 'allow',
      reason: 'Baseline developer access to code segment approved'
    },
    {
      timestamp: new Date(now - 360000).toISOString(),
      session_id: 'sess-bob-base-42',
      decision: 'allow',
      reason: 'Normal finance team login from compliant office workstation'
    },
    {
      timestamp: new Date(now - 480000).toISOString(),
      session_id: 'sess-alice-base-91',
      decision: 'allow',
      reason: 'OIDC token verified, clean posture telemetry received'
    }
  ];

  actions = [
    {
      action_type: 'notify_user',
      session_id: 'sess-alice-base-91',
      status: 'executed',
      timestamp: new Date(now - 480000).toISOString()
    },
    {
      action_type: 'alert_soc',
      session_id: 'sess-bob-base-42',
      status: 'executed',
      timestamp: new Date(now - 360000).toISOString()
    }
  ];

  updateDashboard();
}

// ── Rendering Functions ────────────────────────────────────────────────────────

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
  const pct = Math.min(100, Math.round(score * 100));
  const col = riskColor(score);
  return `
    <div class="risk-bar">
      <div class="risk-track"><div class="risk-fill" style="width:${pct}%;background:${col}"></div></div>
      <span class="risk-val" style="color:${col}">${score.toFixed(2)}</span>
    </div>`;
}

function updateSessionsView() {
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
    const statusIcon = !s.active ? '🔴 Terminated' : s.mfa_required ? '🟡 MFA Required' : s.restricted ? '🟠 Restricted' : '🟢 Active';
    return `<tr>
      <td><strong>${s.user_id}</strong></td>
      <td style="font-size:0.75rem">${s.device_id}</td>
      <td>${riskBar(s.risk_score)}</td>
      <td>${s.posture_score !== null && s.posture_score !== undefined ? s.posture_score.toFixed(2) : '—'}</td>
      <td>${decisionPill(s.decision)}</td>
      <td style="font-size:0.75rem">${statusIcon}</td>
    </tr>`;
  }).join('');
}

function updateDecisionsView() {
  const tl = document.getElementById('decision-timeline');
  document.getElementById('decision-count').textContent = decisions.length;
  document.getElementById('metric-decisions').textContent = decisions.length;

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
    const reason = (d.reason || '').slice(0, 85);
    return `<div class="timeline-item timeline-item--${d.decision}">
      <span class="tl-time">${t}</span>
      <span class="tl-session">${sess}</span>
      ${decisionPill(d.decision)}
      <span class="tl-reason">${reason}</span>
    </div>`;
  }).join('');
}

function updateActionsView() {
  const feed = document.getElementById('action-feed');
  document.getElementById('action-count').textContent = actions.length;

  if (actions.length === 0) {
    feed.innerHTML = '<div class="empty-row">No actions yet…</div>';
    return;
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

function updateDashboard() {
  document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
  updateSessionsView();
  updateDecisionsView();
  updateActionsView();
}

// ── SSE live connection ────────────────────────────────────────────────────────

function connectSSE() {
  try {
    const evtSrc = new EventSource('/events');

    evtSrc.onopen = () => {
      isDemoMode = false;
      document.getElementById('status-dot').classList.remove('offline');
      document.getElementById('status-text').textContent = 'Live (Backend)';
    };

    evtSrc.onerror = () => {
      // Backend not running on this domain/port -> Activate interactive simulation mode
      if (!isDemoMode) {
        activateDemoMode();
      }
      evtSrc.close();
    };

    evtSrc.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.error) return;
        document.getElementById('last-update').textContent =
          new Date(data.timestamp).toLocaleTimeString();
        sessions = data.sessions || [];
        decisions = data.decisions || [];
        actions = data.actions || [];
        updateDashboard();
      } catch (_) {}
    };
  } catch (err) {
    activateDemoMode();
  }
}

function activateDemoMode() {
  isDemoMode = true;
  document.getElementById('status-dot').classList.remove('offline');
  document.getElementById('status-text').textContent = 'Live (Demo Simulation)';
  initDemoData();
}

// ── Interactive Scenario Execution ─────────────────────────────────────────────

async function runScenario(name) {
  const btn = document.getElementById(`btn-${name}`);
  const fb = document.getElementById('scenario-feedback');
  const labels = {
    s1: 'S1 Credential Misuse',
    s2: 'S2 Lateral Movement',
    s3: 'S3 Privilege Escalation',
    s4: 'S4 Slow-and-Low Drift'
  };

  btn.disabled = true;
  btn.textContent = '⏳ Running…';
  fb.textContent = `Triggering ${labels[name]}…`;

  if (!isDemoMode) {
    // Attempt backend API call
    try {
      const r = await fetch(`/api/scenario/${name}`, { method: 'POST' });
      if (r.ok) {
        const data = await r.json();
        fb.textContent = data.status === 'started'
          ? `✅ ${labels[name]} started. Live telemetry updating below.`
          : `⚠️ ${data.detail || 'Completed'}`;
        setTimeout(() => { btn.disabled = false; btn.textContent = labels[name]; }, 4000);
        return;
      }
    } catch (_) {
      // Fallback to simulation mode if backend endpoint unreachable
    }
  }

  // Interactive Client-Side Simulation
  simulateScenario(name, labels[name], btn, fb);
}

function simulateScenario(name, label, btn, fb) {
  const now = Date.now();
  const ts = new Date().toISOString();

  if (name === 's1') {
    // S1: Credential Misuse
    fb.textContent = `[*] Attacker logged in as 'alice' from 203.0.113.42 on dev-unknown-attacker...`;
    setTimeout(() => {
      fb.textContent = `[!] M5 ML Engine: Anomaly detected! Risk score spiked to 0.89 (SHAP: foreign_ip, unknown_device).`;
      
      const attackerSessId = 'sess-atk-' + Math.floor(1000 + Math.random() * 9000);
      sessions.unshift({
        session_id: attackerSessId,
        user_id: 'alice (Compromised)',
        device_id: 'dev-unknown-attacker',
        ip_address: '203.0.113.42',
        risk_score: 0.89,
        posture_score: 0.15,
        decision: 'deny',
        active: false,
        mfa_required: false,
        restricted: true
      });

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: attackerSessId,
        decision: 'deny',
        reason: 'ML anomaly risk=0.89 + unmanaged device dev-unknown-attacker'
      });

      actions.push(
        { action_type: 'terminate_session', session_id: attackerSessId, status: 'executed', timestamp: new Date().toISOString() },
        { action_type: 'block_ip', session_id: attackerSessId, status: 'executed', timestamp: new Date().toISOString() },
        { action_type: 'alert_soc', session_id: attackerSessId, status: 'executed', timestamp: new Date().toISOString() }
      );

      updateDashboard();
      fb.textContent = `🛡️ [Zero Trust PDP] S1 BLOCKED in < 30s! Attacker session revoked, IP blocked. (Static RBAC would have breached).`;
      btn.disabled = false;
      btn.textContent = label;
    }, 1500);

  } else if (name === 's2') {
    // S2: Lateral Movement
    fb.textContent = `[*] Frank (Role: Developer) accessing /code... Attempting lateral jump to /finance...`;
    setTimeout(() => {
      const frankSess = sessions.find(s => s.user_id === 'frank');
      if (frankSess) {
        frankSess.risk_score = 0.65;
        frankSess.restricted = true;
        frankSess.decision = 'restrict';
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: frankSess ? frankSess.session_id : 'sess-frank-lat',
        decision: 'restrict',
        reason: 'Cross-segment access violation: Developer attempted unpermitted /finance segment'
      });

      actions.push(
        { action_type: 'restrict_access', session_id: frankSess ? frankSess.session_id : 'sess-frank', status: 'executed', timestamp: new Date().toISOString() },
        { action_type: 'alert_soc', session_id: frankSess ? frankSess.session_id : 'sess-frank', status: 'executed', timestamp: new Date().toISOString() }
      );

      updateDashboard();
      fb.textContent = `🛡️ [Zero Trust PEP] S2 CONTAINED! Micro-segmentation policy denied lateral traversal to /finance.`;
      btn.disabled = false;
      btn.textContent = label;
    }, 1500);

  } else if (name === 's3') {
    // S3: Privilege Escalation
    fb.textContent = `[*] Eve (Role: Viewer) attempting to invoke administrative API at /admin/keys...`;
    setTimeout(() => {
      const eveSess = sessions.find(s => s.user_id === 'eve');
      if (eveSess) {
        eveSess.risk_score = 0.94;
        eveSess.active = false;
        eveSess.decision = 'deny';
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: eveSess ? eveSess.session_id : 'sess-eve-esc',
        decision: 'deny',
        reason: 'Privilege Escalation attempt: Viewer requested /admin without admin grant'
      });

      actions.push(
        { action_type: 'terminate_session', session_id: eveSess ? eveSess.session_id : 'sess-eve', status: 'executed', timestamp: new Date().toISOString() },
        { action_type: 'alert_soc', session_id: eveSess ? eveSess.session_id : 'sess-eve', status: 'executed', timestamp: new Date().toISOString() }
      );

      updateDashboard();
      fb.textContent = `🛡️ [Zero Trust PDP] S3 BLOCKED! Unauthorized privilege escalation blocked and session revoked immediately.`;
      btn.disabled = false;
      btn.textContent = label;
    }, 1500);

  } else if (name === 's4') {
    // S4: Slow-and-Low Drift
    fb.textContent = `[*] Alice endpoint telemetry reporting firewall disabled and outdated patches...`;
    setTimeout(() => {
      const aliceSess = sessions.find(s => s.user_id === 'alice');
      if (aliceSess) {
        aliceSess.posture_score = 0.41;
        aliceSess.risk_score = 0.52;
        aliceSess.mfa_required = true;
        aliceSess.decision = 'step_up';
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: aliceSess ? aliceSess.session_id : 'sess-alice-base-91',
        decision: 'step_up',
        reason: 'Posture score degraded below threshold (0.41) - Step-Up MFA Challenge enforced'
      });

      actions.push(
        { action_type: 'require_mfa', session_id: aliceSess ? aliceSess.session_id : 'sess-alice', status: 'executed', timestamp: new Date().toISOString() },
        { action_type: 'notify_user', session_id: aliceSess ? aliceSess.session_id : 'sess-alice', status: 'executed', timestamp: new Date().toISOString() }
      );

      updateDashboard();
      fb.textContent = `🛡️ [Continuous Evaluation] S4 DRIFT DETECTED! Posture degradation triggered dynamic Step-Up MFA challenge.`;
      btn.disabled = false;
      btn.textContent = label;
    }, 1500);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // If hosted on Vercel, GitHub Pages, or static file, start directly in demo simulation mode
  if (
    window.location.hostname.endsWith('github.io') ||
    window.location.hostname.endsWith('vercel.app') ||
    window.location.hostname.includes('vercel') ||
    window.location.protocol === 'file:'
  ) {
    activateDemoMode();
  } else {
    connectSSE();
  }
});

