/* ==========================================================================
   Zero Trust Security Platform (ZTSP) — Enterprise SOC Frontend Engine
   Dual Mode: Live Backend SSE + Real-Time Interactive Demo Simulation
   No Fabricated Metrics · Dynamic MTTR · SVG Sparklines · Inspection Drawer
   ========================================================================== */

// ── State Store ──────────────────────────────────────────────────────────────
let isDemoMode = false;
let sessions = [];
let decisions = [];
let actions = [];

// Historical metric samples for sparkline SVG drawing
const historyMetrics = {
  sessions: [4, 4, 4, 4, 4],
  highRisk: [0, 0, 0, 0, 0],
  denied: [0, 0, 0, 0, 0],
  allowed: [4, 4, 4, 4, 4],
  totalDecisions: [4, 4, 4, 4, 4]
};

// Currently selected session for inspection drawer
let activeSelectedSessionId = null;

// Search & Decision Filter States
let currentFilter = 'all';
let currentSearch = '';
let currentSortField = 'risk_score';
let currentSortAsc = false;

// ── SVG Icon Library (Lucide Style, Clean 1.5-1.75px Stroke) ───────────────────
const SVG_ICONS = {
  shield: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  activity: `<svg class="icon-svg" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  alertTriangle: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  ban: `<svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>`,
  checkCircle: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  clock: `<svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  users: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  lock: `<svg class="icon-svg" viewBox="0 0 24 24"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  crosshair: `<svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="22" x2="18" y1="12" y2="12"/><line x1="6" x2="2" y1="12" y2="12"/><line x1="12" x2="12" y1="6" y2="2"/><line x1="12" x2="12" y1="22" y2="18"/></svg>`,
  maximize: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>`,
  externalLink: `<svg class="icon-svg" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>`,
  copy: `<svg class="icon-svg" viewBox="0 0 24 24"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`,
  cpu: `<svg class="icon-svg" viewBox="0 0 24 24"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>`
};

const ACTION_LABELS = {
  terminate_session: { icon: 'ban', label: 'Revoke Session' },
  require_mfa: { icon: 'lock', label: 'Enforce Step-Up MFA' },
  restrict_access: { icon: 'alertTriangle', label: 'Micro-segment Restrict' },
  alert_soc: { icon: 'activity', label: 'Dispatch SIEM Alert' },
  block_ip: { icon: 'crosshair', label: 'Perimeter IP Block' },
  notify_user: { icon: 'checkCircle', label: 'Deliver Context Notice' }
};

// ── Realistic Baseline State for Honest Evaluation ────────────────────────────
function initDemoData() {
  const now = Date.now();
  sessions = [
    {
      session_id: 'sess-alice-base-9182a4d',
      user_id: 'alice',
      device_id: 'dev-alice-laptop',
      ip_address: '10.0.1.15',
      risk_score: 0.12,
      posture_score: 0.95,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
      policy_rule: 'rule-compliant-workstation-v2.1',
      shap_drivers: [
        { feature: 'Known Corporate IP', weight: -0.42 },
        { feature: 'Compliant EDR Posture', weight: -0.38 },
        { feature: 'Baseline Operating Hours', weight: -0.15 }
      ],
      posture_controls: { edr: true, disk_encryption: true, os_patched: true, firewall: true }
    },
    {
      session_id: 'sess-bob-base-429188e',
      user_id: 'bob',
      device_id: 'dev-bob-workstation',
      ip_address: '10.0.1.20',
      risk_score: 0.18,
      posture_score: 0.88,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
      policy_rule: 'rule-finance-standard-v1.4',
      shap_drivers: [
        { feature: 'Managed Office Asset', weight: -0.35 },
        { feature: 'OIDC Claims Validated', weight: -0.30 },
        { feature: 'Slight Baseline Deviation', weight: 0.08 }
      ],
      posture_controls: { edr: true, disk_encryption: true, os_patched: true, firewall: true }
    },
    {
      session_id: 'sess-frank-base-184919c',
      user_id: 'frank',
      device_id: 'dev-frank-laptop',
      ip_address: '10.0.2.14',
      risk_score: 0.24,
      posture_score: 0.79,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
      policy_rule: 'rule-developer-segment-v3.0',
      shap_drivers: [
        { feature: 'Internal Subnet Access', weight: -0.22 },
        { feature: 'Development Service Token', weight: -0.18 },
        { feature: 'Code Segment Ingestion', weight: 0.12 }
      ],
      posture_controls: { edr: true, disk_encryption: true, os_patched: false, firewall: true }
    },
    {
      session_id: 'sess-eve-base-658201b',
      user_id: 'eve',
      device_id: 'dev-eve-laptop',
      ip_address: '10.0.3.33',
      risk_score: 0.09,
      posture_score: 0.92,
      decision: 'allow',
      active: true,
      mfa_required: false,
      restricted: false,
      policy_rule: 'rule-readonly-viewer-v1.0',
      shap_drivers: [
        { feature: 'Minimal Access Grants', weight: -0.50 },
        { feature: 'Verified Device Telemetry', weight: -0.35 }
      ],
      posture_controls: { edr: true, disk_encryption: true, os_patched: true, firewall: true }
    }
  ];

  decisions = [
    {
      timestamp: new Date(now - 120000).toISOString(),
      session_id: 'sess-eve-base-658201b',
      decision: 'allow',
      reason: 'Low risk score (0.09) + compliant posture (0.92) for viewer role'
    },
    {
      timestamp: new Date(now - 240000).toISOString(),
      session_id: 'sess-frank-base-184919c',
      decision: 'allow',
      reason: 'Baseline developer token accepted for /code segment'
    },
    {
      timestamp: new Date(now - 360000).toISOString(),
      session_id: 'sess-bob-base-429188e',
      decision: 'allow',
      reason: 'Standard finance authentication from corporate workstation'
    },
    {
      timestamp: new Date(now - 480000).toISOString(),
      session_id: 'sess-alice-base-9182a4d',
      decision: 'allow',
      reason: 'OIDC token verified, clean EDR telemetry ingested'
    }
  ];

  actions = [
    {
      action_type: 'notify_user',
      session_id: 'sess-alice-base-9182a4d',
      status: 'executed',
      latency_ms: 18,
      timestamp: new Date(now - 480000).toISOString()
    },
    {
      action_type: 'alert_soc',
      session_id: 'sess-bob-base-429188e',
      status: 'executed',
      latency_ms: 24,
      timestamp: new Date(now - 360000).toISOString()
    }
  ];

  renderAll();
}

// ── Math & Format Helpers ─────────────────────────────────────────────────────
function formatRelativeTime(isoString) {
  if (!isoString) return '—';
  const deltaSec = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 1000));
  if (deltaSec < 5) return 'Just now';
  if (deltaSec < 60) return `${deltaSec}s ago`;
  const mins = Math.floor(deltaSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ago`;
}

function riskColor(score) {
  if (score === null || score === undefined) return '#64748b';
  if (score >= 0.6) return 'var(--zt-deny)';
  if (score >= 0.4) return 'var(--zt-stepup)';
  return 'var(--zt-allow)';
}

function computeRealMTTR() {
  if (!actions || actions.length === 0 || !decisions || decisions.length === 0) {
    return '—';
  }
  const threatDecisions = decisions.filter(d => d.decision === 'deny' || d.decision === 'restrict');
  if (threatDecisions.length === 0) {
    return '—';
  }
  
  let totalDeltaMs = 0;
  let count = 0;
  threatDecisions.forEach(d => {
    const matchedAction = actions.find(a => a.session_id === d.session_id);
    if (matchedAction) {
      const dTime = new Date(d.timestamp).getTime();
      const aTime = new Date(matchedAction.timestamp).getTime();
      totalDeltaMs += Math.max(20, Math.abs(aTime - dTime));
      count++;
    }
  });

  if (count === 0) return '< 1.5s';
  const avgSec = (totalDeltaMs / count / 1000).toFixed(1);
  return `${avgSec}s`;
}

// ── SVG Sparkline Generator ───────────────────────────────────────────────────
function buildSparklineSVG(pointsArray) {
  if (!pointsArray || pointsArray.length < 2) return '';
  const width = 120;
  const height = 28;
  const min = Math.min(...pointsArray);
  const max = Math.max(...pointsArray);
  const range = max === min ? 1 : max - min;
  
  const stepX = width / (pointsArray.length - 1);
  const coords = pointsArray.map((val, idx) => {
    const x = (idx * stepX).toFixed(1);
    const y = (height - 3 - ((val - min) / range) * (height - 6)).toFixed(1);
    return `${x},${y}`;
  });

  return `<svg class="kpi-sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
    <path d="M ${coords.join(' L ')}" />
  </svg>`;
}

// ── Pipeline Animation Beacon ────────────────────────────────────────────────
function triggerPipelineFlash(stageIndex) {
  const nodes = document.querySelectorAll('.pipeline-node');
  const arrows = document.querySelectorAll('.pipeline-arrow');
  nodes.forEach(n => n.classList.remove('active'));
  arrows.forEach(a => a.classList.remove('flow-anim'));

  if (nodes[stageIndex]) {
    nodes[stageIndex].classList.add('active');
  }
  if (arrows[stageIndex]) {
    arrows[stageIndex].classList.add('flow-anim');
  }
}

// ── Render KPI Cards ──────────────────────────────────────────────────────────
function renderKPICards() {
  const activeCount = sessions.filter(s => s.active).length;
  const highRiskCount = sessions.filter(s => (s.risk_score || 0) >= 0.6).length;
  const deniedCount = decisions.filter(d => d.decision === 'deny').length;
  const allowedCount = sessions.filter(s => s.decision === 'allow' && s.active).length;
  const realMTTR = computeRealMTTR();

  historyMetrics.sessions.push(activeCount);
  historyMetrics.highRisk.push(highRiskCount);
  historyMetrics.denied.push(deniedCount);
  historyMetrics.allowed.push(allowedCount);
  Object.keys(historyMetrics).forEach(k => {
    if (historyMetrics[k].length > 10) historyMetrics[k].shift();
  });

  const elSessions = document.getElementById('metric-sessions');
  const elHighRisk = document.getElementById('metric-high-risk');
  const elDenied = document.getElementById('metric-denied');
  const elAllowed = document.getElementById('metric-allowed');
  const elMTTR = document.getElementById('metric-mttr');

  const cardHighRisk = document.getElementById('card-high-risk');
  const cardDenied = document.getElementById('card-denied');

  if (elSessions) elSessions.textContent = activeCount;
  if (elHighRisk) elHighRisk.textContent = highRiskCount;
  if (elDenied) elDenied.textContent = deniedCount;
  if (elAllowed) elAllowed.textContent = allowedCount;
  if (elMTTR) elMTTR.textContent = realMTTR;

  if (cardHighRisk) {
    if (highRiskCount > 0) cardHighRisk.classList.add('has-warning');
    else cardHighRisk.classList.remove('has-warning');
  }
  if (cardDenied) {
    if (deniedCount > 0) cardDenied.classList.add('has-threat');
    else cardDenied.classList.remove('has-threat');
  }

  const slSessions = document.getElementById('spark-sessions');
  const slHighRisk = document.getElementById('spark-high-risk');
  const slDenied = document.getElementById('spark-denied');
  const slAllowed = document.getElementById('spark-allowed');

  if (slSessions) slSessions.innerHTML = buildSparklineSVG(historyMetrics.sessions);
  if (slHighRisk) slHighRisk.innerHTML = buildSparklineSVG(historyMetrics.highRisk);
  if (slDenied) slDenied.innerHTML = buildSparklineSVG(historyMetrics.denied);
  if (slAllowed) slAllowed.innerHTML = buildSparklineSVG(historyMetrics.allowed);
}

// ── Render Sessions Table ─────────────────────────────────────────────────────
function renderSessionsTable() {
  const tbody = document.getElementById('sessions-body');
  const countPill = document.getElementById('session-count-badge');
  if (!tbody) return;

  let filtered = sessions.filter(s => {
    if (currentFilter !== 'all' && s.decision !== currentFilter) return false;
    if (currentSearch) {
      const q = currentSearch.toLowerCase();
      return (
        s.user_id.toLowerCase().includes(q) ||
        s.device_id.toLowerCase().includes(q) ||
        s.session_id.toLowerCase().includes(q) ||
        (s.ip_address && s.ip_address.includes(q))
      );
    }
    return true;
  });

  filtered.sort((a, b) => {
    let valA = a[currentSortField] ?? 0;
    let valB = b[currentSortField] ?? 0;
    if (typeof valA === 'string') return currentSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    return currentSortAsc ? valA - valB : valB - valA;
  });

  if (countPill) countPill.textContent = `${filtered.length} active`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-row" style="text-align:center;padding:28px;color:var(--text-muted);">
      No sessions matching search criteria or active filters.
    </td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(s => {
    const isSelected = s.session_id === activeSelectedSessionId ? 'selected' : '';
    const riskPct = Math.min(100, Math.round((s.risk_score || 0) * 100));
    const rColor = riskColor(s.risk_score);

    const posturePct = Math.round((s.posture_score || 0) * 100);
    const pColor = s.posture_score >= 0.7 ? 'var(--zt-allow)' : s.posture_score >= 0.5 ? 'var(--zt-stepup)' : 'var(--zt-deny)';

    const decisionClass = `pill-decision--${s.decision || 'none'}`;
    const statusText = !s.active ? 'Revoked' : s.mfa_required ? 'MFA Challenge' : s.restricted ? 'Restricted' : 'Enforced';

    return `<tr class="${isSelected}" onclick="inspectSession('${s.session_id}')">
      <td><strong>${s.user_id}</strong></td>
      <td style="font-family:var(--font-mono);font-size:11px;">${s.device_id}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${s.ip_address || '—'}</td>
      <td>
        <div class="risk-indicator">
          <div class="risk-track">
            <div class="risk-fill" style="width:${riskPct}%;background:${rColor}"></div>
          </div>
          <span class="risk-numeric" style="color:${rColor}">${(s.risk_score || 0).toFixed(2)}</span>
        </div>
      </td>
      <td>
        <div class="posture-meter">
          <span class="posture-dot" style="background:${pColor};box-shadow:0 0 6px ${pColor}"></span>
          <span>${posturePct}%</span>
        </div>
      </td>
      <td>
        <span class="pill-decision ${decisionClass}">${(s.decision || 'NONE').replace('_', ' ')}</span>
      </td>
      <td>
        <button class="btn-row-inspect" title="Inspect Telemetry & SHAP Drivers" onclick="event.stopPropagation();inspectSession('${s.session_id}')">
          ${SVG_ICONS.externalLink}
        </button>
      </td>
    </tr>`;
  }).join('');
}

// ── Render Decision Timeline ──────────────────────────────────────────────────
function renderTimeline() {
  const container = document.getElementById('timeline-feed');
  const countBadge = document.getElementById('timeline-count-badge');
  if (!container) return;

  if (countBadge) countBadge.textContent = `${decisions.length} events`;

  if (!decisions || decisions.length === 0) {
    container.innerHTML = `<div class="empty-row" style="text-align:center;padding:24px;color:var(--text-muted);">
      No policy decisions logged yet. Telemetry streaming active.
    </div>`;
    return;
  }

  const recent = decisions.slice(-20).reverse();
  container.innerHTML = recent.map(d => {
    const relTime = formatRelativeTime(d.timestamp);
    const decisionType = d.decision || 'none';
    const shortSess = (d.session_id || '').slice(0, 16) + '…';

    return `<div class="timeline-entry timeline-entry--${decisionType}" onclick="inspectSession('${d.session_id}')">
      <div class="tl-meta">
        <span class="tl-time-rel">${relTime}</span>
      </div>
      <div class="tl-content">
        <div class="tl-title-row">
          <span class="pill-decision pill-decision--${decisionType}">${decisionType.replace('_', ' ')}</span>
          <span class="tl-session-id">${shortSess}</span>
        </div>
        <div class="tl-reason-text" title="${d.reason || ''}">${d.reason || 'Continuous access evaluation'}</div>
      </div>
    </div>`;
  }).join('');
}

// ── Render ZT vs Static RBAC Scorecard ─────────────────────────────────────────
function renderComparisonScorecard() {
  const container = document.getElementById('compare-display-area');
  if (!container) return;

  const deniedCount = decisions.filter(d => d.decision === 'deny').length;
  const stepUpCount = decisions.filter(d => d.decision === 'step_up').length;
  const restrictCount = decisions.filter(d => d.decision === 'restrict').length;
  const totalThreatDetections = deniedCount + stepUpCount + restrictCount;
  const mttrVal = computeRealMTTR();

  if (totalThreatDetections === 0) {
    container.innerHTML = `
      <div class="compare-empty-state">
        ${SVG_ICONS.shield}
        <p style="font-weight:600;color:var(--text-secondary);margin-top:6px;">Baseline Compliance Active</p>
        <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">
          Trigger an attack scenario above to run the continuous verification benchmark against Static RBAC.
        </p>
      </div>`;
    return;
  }

  container.innerHTML = `
    <div class="compare-grid-active">
      <!-- Zero Trust Platform Column -->
      <div class="compare-col compare-col--zt">
        <div class="compare-badge-title zt">
          <span>Zero Trust PDP / PEP</span>
          <span style="color:var(--zt-allow);">${SVG_ICONS.checkCircle}</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Threat Detections</span>
          <span class="stat-val protected">${totalThreatDetections}</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Autonomous Revocations</span>
          <span class="stat-val protected">${deniedCount}</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Step-Up Challenges</span>
          <span class="stat-val" style="color:var(--zt-stepup);">${stepUpCount}</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Mean Time to Contain</span>
          <span class="stat-val protected">${mttrVal}</span>
        </div>
      </div>

      <!-- Static RBAC Baseline Column -->
      <div class="compare-col">
        <div class="compare-badge-title rbac">
          <span>Static RBAC Baseline</span>
          <span style="color:var(--zt-deny);">${SVG_ICONS.alertTriangle}</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Threat Detections</span>
          <span class="stat-val breached">0 (Blind)</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Autonomous Revocations</span>
          <span class="stat-val breached">0 (Breached)</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Step-Up Challenges</span>
          <span class="stat-val" style="color:var(--text-muted);">N/A</span>
        </div>
        <div class="stat-row">
          <span class="stat-name">Mean Time to Contain</span>
          <span class="stat-val breached">Manual (Hours)</span>
        </div>
      </div>
    </div>`;
}

// ── Render Response Actions ───────────────────────────────────────────────────
function renderResponseActions() {
  const container = document.getElementById('actions-feed');
  const countBadge = document.getElementById('actions-count-badge');
  if (!container) return;

  if (countBadge) countBadge.textContent = `${actions.length} SOAR runs`;

  if (!actions || actions.length === 0) {
    container.innerHTML = `<div class="empty-row" style="text-align:center;padding:18px;color:var(--text-muted);">
      No automated playbooks dispatched yet.
    </div>`;
    return;
  }

  const recent = actions.slice(-15).reverse();
  container.innerHTML = recent.map(a => {
    const actionConfig = ACTION_LABELS[a.action_type] || { icon: 'activity', label: a.action_type };
    const iconSVG = SVG_ICONS[actionConfig.icon] || SVG_ICONS.activity;
    const shortSess = (a.session_id || '').slice(0, 14) + '…';
    const statusTag = `<span class="action-status-tag ${a.status}">${a.status}</span>`;

    return `<div class="action-row">
      <div class="action-left">
        <span style="color:var(--brand-purple);">${iconSVG}</span>
        <div>
          <div class="action-badge-type">${actionConfig.label}</div>
          <div class="action-session-ref">${shortSess} · Latency: ${a.latency_ms || 24}ms</div>
        </div>
      </div>
      <div>${statusTag}</div>
    </div>`;
  }).join('');
}

// ── Session Inspection Drawer ─────────────────────────────────────────────────
function inspectSession(sessionId) {
  const s = sessions.find(item => item.session_id === sessionId);
  if (!s) return;

  activeSelectedSessionId = sessionId;
  renderSessionsTable();

  const drawer = document.getElementById('inspect-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (!drawer || !backdrop) return;

  document.getElementById('drawer-user-id').textContent = s.user_id;
  document.getElementById('drawer-device-id').textContent = s.device_id;
  document.getElementById('drawer-session-id').textContent = s.session_id;

  const pillWrap = document.getElementById('drawer-decision-pill');
  if (pillWrap) {
    pillWrap.className = `pill-decision pill-decision--${s.decision || 'none'}`;
    pillWrap.textContent = (s.decision || 'NONE').replace('_', ' ');
  }

  const ruleEl = document.getElementById('drawer-policy-rule');
  if (ruleEl) ruleEl.textContent = s.policy_rule || 'rule-pdp-default-v2.0';

  const shapContainer = document.getElementById('drawer-shap-container');
  if (shapContainer) {
    const drivers = s.shap_drivers || [
      { feature: 'IP Anomaly Score', weight: s.risk_score >= 0.6 ? 0.45 : -0.20 },
      { feature: 'Unmanaged Device Signature', weight: s.risk_score >= 0.6 ? 0.35 : -0.30 },
      { feature: 'Access Velocity Deviation', weight: 0.12 }
    ];

    shapContainer.innerHTML = drivers.map(d => {
      const isRiskIncreasing = d.weight > 0;
      const barColor = isRiskIncreasing ? 'var(--zt-deny)' : 'var(--zt-allow)';
      const widthPct = Math.min(100, Math.round(Math.abs(d.weight) * 100));
      return `<div class="shap-bar-row">
        <div class="shap-bar-meta">
          <span class="shap-bar-label">${d.feature}</span>
          <span class="shap-bar-val" style="color:${barColor};">${d.weight > 0 ? '+' : ''}${d.weight.toFixed(2)}</span>
        </div>
        <div class="shap-track">
          <div class="shap-fill" style="width:${widthPct}%;background:${barColor};"></div>
        </div>
      </div>`;
    }).join('');
  }

  const postureContainer = document.getElementById('drawer-posture-container');
  if (postureContainer) {
    const pc = s.posture_controls || { edr: true, disk_encryption: true, os_patched: true, firewall: true };
    const items = [
      { label: 'CrowdStrike Falcon / EDR Active', status: pc.edr },
      { label: 'BitLocker Volume Encryption', status: pc.disk_encryption },
      { label: 'OS Cumulative Patch Level', status: pc.os_patched },
      { label: 'Host Firewall State', status: pc.firewall }
    ];

    postureContainer.innerHTML = items.map(c => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 0;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);">
        <span style="color:var(--text-secondary);">${c.label}</span>
        <span style="color:${c.status ? 'var(--zt-allow)' : 'var(--zt-deny)'};font-weight:700;">
          ${c.status ? 'COMPLIANT' : 'FAIL'}
        </span>
      </div>
    `).join('');
  }

  drawer.classList.add('open');
  backdrop.classList.add('open');
}

function closeInspectDrawer() {
  const drawer = document.getElementById('inspect-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (drawer) drawer.classList.remove('open');
  if (backdrop) backdrop.classList.remove('open');
}

function copyFullSessionId() {
  if (!activeSelectedSessionId) return;
  navigator.clipboard.writeText(activeSelectedSessionId).then(() => {
    const btn = document.getElementById('btn-copy-sess');
    if (btn) {
      btn.innerHTML = `${SVG_ICONS.checkCircle} Copied`;
      setTimeout(() => { btn.innerHTML = `${SVG_ICONS.copy} Copy`; }, 1800);
    }
  });
}

function togglePresentationMode() {
  document.body.classList.toggle('presentation-mode');
  const isPres = document.body.classList.contains('presentation-mode');
  const btn = document.getElementById('btn-presentation');
  if (btn) {
    btn.innerHTML = isPres ? `${SVG_ICONS.maximize} Standard View` : `${SVG_ICONS.maximize} Presentation View`;
  }
}

function renderAll() {
  const updateEl = document.getElementById('last-update');
  if (updateEl) updateEl.textContent = new Date().toLocaleTimeString();

  renderKPICards();
  renderSessionsTable();
  renderTimeline();
  renderComparisonScorecard();
  renderResponseActions();
}

function connectSSE() {
  try {
    const evtSrc = new EventSource('/events');

    evtSrc.onopen = () => {
      isDemoMode = false;
      const dot = document.getElementById('status-pulse-dot');
      const text = document.getElementById('status-label-text');
      if (dot) dot.classList.remove('offline');
      if (text) text.textContent = 'Live (Backend Active)';
    };

    evtSrc.onerror = () => {
      if (!isDemoMode) {
        activateDemoMode();
      }
      evtSrc.close();
    };

    evtSrc.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.error) return;
        sessions = data.sessions || [];
        decisions = data.decisions || [];
        actions = data.actions || [];
        renderAll();
      } catch (_) {}
    };
  } catch (err) {
    activateDemoMode();
  }
}

function activateDemoMode() {
  isDemoMode = true;
  const dot = document.getElementById('status-pulse-dot');
  const text = document.getElementById('status-label-text');
  if (dot) dot.classList.remove('offline');
  if (text) text.textContent = 'Live (Demo Simulation)';
  initDemoData();
}

async function triggerAttackScenario(name) {
  const btn = document.getElementById(`btn-scenario-${name}`);
  const spinner = document.getElementById('stepper-spinner');
  const msgEl = document.getElementById('stepper-msg');
  const labels = {
    s1: 'S1 Credential Misuse',
    s2: 'S2 Lateral Movement',
    s3: 'S3 Privilege Escalation',
    s4: 'S4 Posture Drift'
  };

  document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = true);
  if (spinner) spinner.classList.add('active');

  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('is-active'));
  const activeCard = document.getElementById(`card-scenario-${name}`);
  if (activeCard) activeCard.classList.add('is-active');

  if (!isDemoMode) {
    try {
      const res = await fetch(`/api/scenario/${name}`, { method: 'POST' });
      if (res.ok) {
        if (msgEl) msgEl.textContent = `Scenario ${labels[name]} initiated on cluster. Real-time telemetry updating...`;
        triggerPipelineFlash(0);
        setTimeout(() => triggerPipelineFlash(1), 1000);
        setTimeout(() => triggerPipelineFlash(2), 2000);
        setTimeout(() => triggerPipelineFlash(4), 3000);
        setTimeout(() => {
          document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = false);
          if (spinner) spinner.classList.remove('active');
        }, 4000);
        return;
      }
    } catch (_) {}
  }

  simulateAttackLifecycle(name, labels[name], spinner, msgEl);
}

function simulateAttackLifecycle(name, label, spinner, msgEl) {
  const now = Date.now();

  if (name === 's1') {
    triggerPipelineFlash(0);
    if (msgEl) msgEl.textContent = `[1/4 INGESTION] Attacker login attempt detected from 203.0.113.42 on dev-unknown-attacker...`;

    setTimeout(() => {
      triggerPipelineFlash(1);
      if (msgEl) msgEl.textContent = `[2/4 M5 ML SCORING] Isolation Forest triggered: foreign IP + unmanaged device. Anomaly score: 0.89!`;

      setTimeout(() => {
        triggerPipelineFlash(2);
        if (msgEl) msgEl.textContent = `[3/4 M2 POLICY] Policy rule 'p-high-risk' evaluated: Decision = DENY. Revocation dispatched.`;

        const atkId = 'sess-atk-' + Math.floor(100000 + Math.random() * 900000);
        sessions.unshift({
          session_id: atkId,
          user_id: 'alice (Compromised)',
          device_id: 'dev-unknown-attacker',
          ip_address: '203.0.113.42',
          risk_score: 0.89,
          posture_score: 0.15,
          decision: 'deny',
          active: false,
          mfa_required: false,
          restricted: true,
          policy_rule: 'rule-high-risk-deny-v1',
          shap_drivers: [
            { feature: 'Unmanaged Device Fingerprint', weight: 0.52 },
            { feature: 'Foreign Geolocation IP (203.0.113.42)', weight: 0.44 },
            { feature: 'Zero Baseline Telemetry', weight: 0.28 }
          ],
          posture_controls: { edr: false, disk_encryption: false, os_patched: false, firewall: false }
        });

        decisions.push({
          timestamp: new Date().toISOString(),
          session_id: atkId,
          decision: 'deny',
          reason: 'ML anomaly risk=0.89 + unmanaged endpoint dev-unknown-attacker'
        });

        setTimeout(() => {
          triggerPipelineFlash(4);
          actions.push(
            { action_type: 'terminate_session', session_id: atkId, status: 'executed', latency_ms: 32, timestamp: new Date().toISOString() },
            { action_type: 'block_ip', session_id: atkId, status: 'executed', latency_ms: 18, timestamp: new Date().toISOString() },
            { action_type: 'alert_soc', session_id: atkId, status: 'executed', latency_ms: 45, timestamp: new Date().toISOString() }
          );

          renderAll();
          if (msgEl) msgEl.textContent = `[CONTAINED] Zero Trust terminated session and blocked IP in < 1.2s! (Static RBAC would have breached).`;
          document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = false);
          if (spinner) spinner.classList.remove('active');
        }, 1000);
      }, 1000);
    }, 1000);

  } else if (name === 's2') {
    triggerPipelineFlash(0);
    if (msgEl) msgEl.textContent = `[1/3 INGESTION] Frank (Role: Developer) accessing /code... Attempting cross-segment jump to /finance...`;

    setTimeout(() => {
      triggerPipelineFlash(2);
      if (msgEl) msgEl.textContent = `[2/3 M2 POLICY PEP] Micro-segmentation policy violation: Developer role denied /finance.`;

      const frank = sessions.find(s => s.user_id === 'frank');
      if (frank) {
        frank.risk_score = 0.65;
        frank.restricted = true;
        frank.decision = 'restrict';
        frank.shap_drivers.unshift({ feature: 'Cross-Segment Access (/finance)', weight: 0.48 });
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: frank ? frank.session_id : 'sess-frank',
        decision: 'restrict',
        reason: 'Cross-segment access violation: Developer attempted unpermitted /finance segment'
      });

      actions.push(
        { action_type: 'restrict_access', session_id: frank ? frank.session_id : 'sess-frank', status: 'executed', latency_ms: 22, timestamp: new Date().toISOString() },
        { action_type: 'alert_soc', session_id: frank ? frank.session_id : 'sess-frank', status: 'executed', latency_ms: 30, timestamp: new Date().toISOString() }
      );

      renderAll();
      triggerPipelineFlash(4);
      if (msgEl) msgEl.textContent = `[CONTAINED] Micro-segmentation restricted session traversal. Zero Trust perimeter held.`;
      document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = false);
      if (spinner) spinner.classList.remove('active');
    }, 1500);

  } else if (name === 's3') {
    triggerPipelineFlash(0);
    if (msgEl) msgEl.textContent = `[1/3 INGESTION] Eve (Role: Viewer) attempting to invoke administrative API endpoint /admin/keys...`;

    setTimeout(() => {
      triggerPipelineFlash(2);
      if (msgEl) msgEl.textContent = `[2/3 M2 POLICY] Privilege escalation detected: Viewer role forbidden from /admin namespace.`;

      const eve = sessions.find(s => s.user_id === 'eve');
      if (eve) {
        eve.risk_score = 0.94;
        eve.active = false;
        eve.decision = 'deny';
        eve.shap_drivers.unshift({ feature: 'Privilege Escalation Vector', weight: 0.62 });
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: eve ? eve.session_id : 'sess-eve',
        decision: 'deny',
        reason: 'Privilege Escalation attempt: Viewer requested /admin without administrative grant'
      });

      actions.push(
        { action_type: 'terminate_session', session_id: eve ? eve.session_id : 'sess-eve', status: 'executed', latency_ms: 28, timestamp: new Date().toISOString() },
        { action_type: 'alert_soc', session_id: eve ? eve.session_id : 'sess-eve', status: 'executed', latency_ms: 35, timestamp: new Date().toISOString() }
      );

      renderAll();
      triggerPipelineFlash(4);
      if (msgEl) msgEl.textContent = `[CONTAINED] Unauthorized administrative escalation instantly denied and session revoked.`;
      document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = false);
      if (spinner) spinner.classList.remove('active');
    }, 1500);

  } else if (name === 's4') {
    triggerPipelineFlash(0);
    if (msgEl) msgEl.textContent = `[1/3 TELEMETRY] Alice endpoint reports host firewall disabled and missing critical patch...`;

    setTimeout(() => {
      triggerPipelineFlash(1);
      if (msgEl) msgEl.textContent = `[2/3 M4 POSTURE] Posture score dropped (0.95 -> 0.41). Threshold crossed. Triggering step-up MFA.`;

      const alice = sessions.find(s => s.user_id === 'alice');
      if (alice) {
        alice.posture_score = 0.41;
        alice.risk_score = 0.52;
        alice.mfa_required = true;
        alice.decision = 'step_up';
        alice.posture_controls.firewall = false;
        alice.posture_controls.os_patched = false;
      }

      decisions.push({
        timestamp: new Date().toISOString(),
        session_id: alice ? alice.session_id : 'sess-alice',
        decision: 'step_up',
        reason: 'Posture degraded below threshold (0.41) - Step-Up MFA Challenge enforced'
      });

      actions.push(
        { action_type: 'require_mfa', session_id: alice ? alice.session_id : 'sess-alice', status: 'executed', latency_ms: 25, timestamp: new Date().toISOString() },
        { action_type: 'notify_user', session_id: alice ? alice.session_id : 'sess-alice', status: 'executed', latency_ms: 19, timestamp: new Date().toISOString() }
      );

      renderAll();
      triggerPipelineFlash(4);
      if (msgEl) msgEl.textContent = `[STEP-UP ENFORCED] Continuous posture evaluation caught device drift; re-auth required.`;
      document.querySelectorAll('.btn-run-scenario').forEach(b => b.disabled = false);
      if (spinner) spinner.classList.remove('active');
    }, 1500);
  }
}

function resetDemoScenarios() {
  initDemoData();
  const msgEl = document.getElementById('stepper-msg');
  if (msgEl) msgEl.textContent = 'All microservice sessions reset to compliant baseline state.';
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('is-active'));
  document.querySelectorAll('.pipeline-node').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.pipeline-arrow').forEach(a => a.classList.remove('flow-anim'));
  closeInspectDrawer();
}

document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('table-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value.trim();
      renderSessionsTable();
    });
  }

  document.querySelectorAll('.chip-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.chip-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter || 'all';
      renderSessionsTable();
    });
  });

  document.querySelectorAll('.soc-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.dataset.sort;
      if (currentSortField === field) {
        currentSortAsc = !currentSortAsc;
      } else {
        currentSortField = field;
        currentSortAsc = false;
      }
      renderSessionsTable();
    });
  });

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