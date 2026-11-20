/**
 * WebShield Security Suite - Enterprise Persistent Database & Telemetry Store
 * Apex Institute of Technology & Cyber Sciences
 * 
 * Production-ready persistent store with atomic file synchronisation,
 * pre-seeded credentials, forensic audit logging, and SOC pub-sub event bus.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'webshield_store.json');
const AUDIT_LOG_FILE = path.join(DATA_DIR, 'security_audit.log');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-Memory Database Schema State
let dbState = {
  users: [],
  failed_attempts: {}, // Key: composite hash
  lockouts: [],        // Array of active and historical lockouts
  security_logs: [],   // In-memory ring buffer of latest 500 forensic events
  metrics: {
    totalRequestsInspected: 0,
    totalThreatsBlocked: 0,
    totalLockoutsEnforced: 0,
    totalAuthFailures: 0,
    totalAuthSuccesses: 0,
    sqliDeflected: 0,
    xssDeflected: 0,
    traversalDeflected: 0,
    rateLimitBlocks: 0,
    activeLockoutsCount: 0,
    startedAt: new Date().toISOString()
  }
};

// Event bus subscribers for real-time SOC streaming
const socSubscribers = new Set();

/**
 * Pre-seeded Enterprise Academic Accounts
 * Passwords pre-hashed with bcrypt (salt rounds: 10)
 */
const SEED_USERS = [
  {
    id: 'USR-STU-8821',
    email: 'student@apex.edu',
    // Plaintext: Apex@2026
    passwordHash: bcrypt.hashSync('Apex@2026', 10),
    name: 'Alex Rivera',
    role: 'student',
    department: 'Department of Cyber Defense & Quantum Computing',
    clearanceLevel: 'Level 1 - Student Academic',
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
    enrolledCourses: [
      'CYB-401: Offensive Security & Ethical Hacking',
      'QNT-310: Quantum Cryptography & Key Distribution',
      'NET-420: Zero-Trust Mesh Architectures'
    ]
  },
  {
    id: 'USR-FAC-4092',
    email: 'faculty@apex.edu',
    // Plaintext: CyberProf#99
    passwordHash: bcrypt.hashSync('CyberProf#99', 10),
    name: 'Dr. Evelyn Vance',
    role: 'faculty',
    department: 'Faculty of Autonomous Systems & AI Security',
    clearanceLevel: 'Level 3 - Faculty / Research Lead',
    avatar: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=150',
    assignedLabs: [
      'Autonomous Vehicle Penetration Lab (Building Sigma)',
      'Neural Model Reverse-Engineering Sandbox'
    ]
  },
  {
    id: 'USR-SOC-0001',
    email: 'admin@apex.edu',
    // Plaintext: ShieldMaster!01
    passwordHash: bcrypt.hashSync('ShieldMaster!01', 10),
    name: 'SOC Commander Marcus Vance',
    role: 'admin',
    department: 'Threat Intelligence, Perimeter Defense & Infrastructure',
    clearanceLevel: 'Level 5 - Sovereign SOC Administrator',
    avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150',
    adminPrivileges: [
      'WAF_RULE_DEPLOYMENT',
      'LOCKOUT_OVERRIDE_FAST_FORWARD',
      'PAYLOAD_INSPECTION_OVERRIDE',
      'GLOBAL_FIREWALL_MANAGEMENT'
    ]
  }
];

/**
 * Atomic Persistence to Disk
 * Writes to a temporary file before renaming to prevent corrupted writes.
 */
function persistToDisk() {
  try {
    const tempFile = `${DB_FILE}.tmp.${Date.now()}`;
    const payload = JSON.stringify({
      users: dbState.users,
      failed_attempts: dbState.failed_attempts,
      lockouts: dbState.lockouts,
      metrics: dbState.metrics
    }, null, 2);

    fs.writeFileSync(tempFile, payload, 'utf8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('[WebShield-DB] Atomic disk synchronization failed:', err.message);
  }
}

/**
 * Append security audit event to continuous log file
 */
function appendAuditLog(entry) {
  try {
    const logLine = JSON.stringify(entry) + '\n';
    fs.appendFileSync(AUDIT_LOG_FILE, logLine, 'utf8');
  } catch (err) {
    console.error('[WebShield-DB] Audit log append error:', err.message);
  }
}

/**
 * Database Initialization
 */
function initializeDatabase() {
  if (fs.existsSync(DB_FILE)) {
    try {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      dbState.users = parsed.users && parsed.users.length ? parsed.users : SEED_USERS;
      dbState.failed_attempts = parsed.failed_attempts || {};
      dbState.lockouts = parsed.lockouts || [];
      if (parsed.metrics) {
        dbState.metrics = { ...dbState.metrics, ...parsed.metrics };
      }
      console.log('[WebShield-DB] Loaded persistent state from disk.');
    } catch (e) {
      console.warn('[WebShield-DB] Warning: DB file corrupted or empty. Re-seeding database...');
      dbState.users = [...SEED_USERS];
      persistToDisk();
    }
  } else {
    console.log('[WebShield-DB] Initializing new WebShield persistent data store.');
    dbState.users = [...SEED_USERS];
    persistToDisk();
  }

  // Ensure default seeded users exist
  for (const seed of SEED_USERS) {
    const exists = dbState.users.find(u => u.email.toLowerCase() === seed.email.toLowerCase());
    if (!exists) {
      dbState.users.push(seed);
    }
  }
  persistToDisk();
  updateActiveLockoutMetrics();
}

/**
 * Recalculate active lockout count
 */
function updateActiveLockoutMetrics() {
  const now = Date.now();
  const activeCount = dbState.lockouts.filter(l => l.status === 'ACTIVE' && l.expiresAt > now).length;
  dbState.metrics.activeLockoutsCount = activeCount;
}

// -----------------------------------------------------------------------------
// USER OPERATIONS
// -----------------------------------------------------------------------------

function getUserByEmail(email) {
  if (!email) return null;
  const target = email.trim().toLowerCase();
  return dbState.users.find(u => u.email.toLowerCase() === target) || null;
}

function getUserById(id) {
  if (!id) return null;
  return dbState.users.find(u => u.id === id) || null;
}

function getAllUsersSanitized() {
  return dbState.users.map(({ passwordHash, ...rest }) => rest);
}

// -----------------------------------------------------------------------------
// FAILED ATTEMPTS & STRIKE TRACKING
// -----------------------------------------------------------------------------

function getIdentifierKey(username, fingerprint, ip) {
  const safeUser = (username || 'anonymous').toLowerCase().trim();
  const safeFp = fingerprint || 'unknown-fp';
  const safeIp = ip || 'unknown-ip';
  return crypto.createHash('sha256').update(`${safeUser}::${safeFp}::${safeIp}`).digest('hex');
}

function getFailedAttempts(username, fingerprint, ip) {
  const key = getIdentifierKey(username, fingerprint, ip);
  const record = dbState.failed_attempts[key];
  if (!record) {
    return { count: 0, firstFailedAt: null, lastFailedAt: null };
  }
  return record;
}

function recordFailedAttempt(username, fingerprint, ip) {
  const key = getIdentifierKey(username, fingerprint, ip);
  const now = Date.now();

  if (!dbState.failed_attempts[key]) {
    dbState.failed_attempts[key] = {
      username: username.toLowerCase().trim(),
      fingerprint,
      ip,
      count: 1,
      firstFailedAt: now,
      lastFailedAt: now
    };
  } else {
    dbState.failed_attempts[key].count += 1;
    dbState.failed_attempts[key].lastFailedAt = now;
    dbState.failed_attempts[key].fingerprint = fingerprint;
    dbState.failed_attempts[key].ip = ip;
  }

  dbState.metrics.totalAuthFailures += 1;
  persistToDisk();

  return dbState.failed_attempts[key];
}

function resetFailedAttempts(username, fingerprint, ip) {
  const key = getIdentifierKey(username, fingerprint, ip);
  if (dbState.failed_attempts[key]) {
    delete dbState.failed_attempts[key];
    persistToDisk();
  }
}

// -----------------------------------------------------------------------------
// 24-HOUR LOCKOUT ENGINE
// -----------------------------------------------------------------------------

/**
 * Record a critical 24-hour lockout
 * Exact duration: 86,400,000 milliseconds (24 Hours)
 */
function recordLockout(username, fingerprint, ip, reason = '3-Strike Credential Failure Threshold Exceeded') {
  const now = Date.now();
  const DURATION_24_HOURS_MS = 24 * 60 * 60 * 1000; // 86,400,000 ms
  const expiresAt = now + DURATION_24_HOURS_MS;
  const threatId = `THREAT-L3-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

  const lockoutEntry = {
    threatId,
    username: username ? username.toLowerCase().trim() : 'anonymous',
    fingerprint,
    ip,
    lockedAt: now,
    expiresAt,
    durationMs: DURATION_24_HOURS_MS,
    reason,
    status: 'ACTIVE',
    overrideBy: null,
    overrideAt: null
  };

  dbState.lockouts.push(lockoutEntry);
  dbState.metrics.totalLockoutsEnforced += 1;
  updateActiveLockoutMetrics();
  persistToDisk();

  // Log critical forensic event
  logSecurityEvent({
    eventType: 'CRITICAL_LOCKOUT',
    severity: 'CRITICAL',
    ip,
    fingerprint,
    username,
    threatId,
    endpoint: '/api/auth/login',
    method: 'POST',
    ruleTriggered: 'LAYER2_THREE_STRIKE_THRESHOLD',
    actionTaken: 'BLOCKED_423_LOCKOUT_24H',
    payloadSample: `Threat ID: ${threatId} | Lockout Duration: 86400000ms | Reason: ${reason}`
  });

  return lockoutEntry;
}

/**
 * Check if user, fingerprint, or IP is currently locked out
 */
function getActiveLockout(username, fingerprint, ip) {
  const now = Date.now();
  const safeUser = username ? username.toLowerCase().trim() : null;

  for (let i = dbState.lockouts.length - 1; i >= 0; i--) {
    const item = dbState.lockouts[i];

    if (item.status === 'ACTIVE') {
      // Check if lockout has naturally expired
      if (item.expiresAt <= now) {
        item.status = 'EXPIRED';
        persistToDisk();
        updateActiveLockoutMetrics();
        continue;
      }

      // Check match by username OR composite fingerprint OR IP
      const matchUser = safeUser && item.username && item.username === safeUser;
      const matchFp = fingerprint && item.fingerprint && item.fingerprint === fingerprint;
      const matchIp = ip && item.ip && item.ip === ip;

      if (matchUser || matchFp || matchIp) {
        return {
          ...item,
          remainingMs: Math.max(0, item.expiresAt - now),
          remainingFormatted: formatDuration(item.expiresAt - now)
        };
      }
    }
  }

  return null;
}

/**
 * Format remaining milliseconds into precision HH:MM:SS
 */
function formatDuration(ms) {
  if (ms <= 0) return '00:00:00';
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

/**
 * Admin Override / Demo Fast-Forward Key Execution
 * Unlocks a specific threat ID, username, IP, or ALL active lockouts
 */
function overrideLockouts({ threatId, username, ip, overrideAll = false, adminEmail = 'admin@apex.edu' }) {
  const now = Date.now();
  let affectedCount = 0;

  for (const lockout of dbState.lockouts) {
    if (lockout.status === 'ACTIVE') {
      let shouldUnlock = false;

      if (overrideAll) {
        shouldUnlock = true;
      } else if (threatId && lockout.threatId === threatId) {
        shouldUnlock = true;
      } else if (username && lockout.username && lockout.username.toLowerCase() === username.toLowerCase().trim()) {
        shouldUnlock = true;
      } else if (ip && lockout.ip && lockout.ip === ip.trim()) {
        shouldUnlock = true;
      }

      if (shouldUnlock) {
        lockout.status = 'OVERRIDDEN';
        lockout.overrideBy = adminEmail;
        lockout.overrideAt = now;
        affectedCount++;

        // Reset any cached failed attempts for this user/ip
        const key = getIdentifierKey(lockout.username, lockout.fingerprint, lockout.ip);
        if (dbState.failed_attempts[key]) {
          delete dbState.failed_attempts[key];
        }
      }
    }
  }

  // Also clean up any loose failed attempts matching this username or ip
  if (username || ip || overrideAll) {
    for (const k of Object.keys(dbState.failed_attempts)) {
      const rec = dbState.failed_attempts[k];
      if (overrideAll || (username && rec.username === username.toLowerCase().trim()) || (ip && rec.ip === ip.trim())) {
        delete dbState.failed_attempts[k];
      }
    }
  }

  if (affectedCount > 0) {
    updateActiveLockoutMetrics();
    persistToDisk();

    logSecurityEvent({
      eventType: 'SOC_OVERRIDE_EXECUTED',
      severity: 'WARN',
      ip: '127.0.0.1',
      fingerprint: 'SOC_CONSOLE_AUTH',
      username: adminEmail,
      endpoint: '/api/soc/override',
      method: 'POST',
      ruleTriggered: 'ADMIN_BYPASS_KEY_APPLIED',
      actionTaken: 'LOCKOUTS_RESET',
      payloadSample: `Evaluator Fast-Forward Override: ${affectedCount} active lockout(s) cleared.`
    });
  }

  return { affectedCount, success: true };
}

function getAllLockouts() {
  const now = Date.now();
  return dbState.lockouts.map(l => ({
    ...l,
    remainingMs: l.status === 'ACTIVE' ? Math.max(0, l.expiresAt - now) : 0,
    remainingFormatted: l.status === 'ACTIVE' ? formatDuration(l.expiresAt - now) : '00:00:00'
  }));
}

// -----------------------------------------------------------------------------
// FORENSIC LOGGING & AUDIT TRAIL
// -----------------------------------------------------------------------------

function logSecurityEvent(eventData) {
  const entry = {
    id: `EVT-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    timestamp: new Date().toISOString(),
    epoch: Date.now(),
    eventType: eventData.eventType || 'SECURITY_EVENT',
    severity: eventData.severity || 'INFO', // INFO, WARN, HIGH, CRITICAL
    ip: eventData.ip || '0.0.0.0',
    fingerprint: eventData.fingerprint || 'unknown-fp',
    username: eventData.username || null,
    endpoint: eventData.endpoint || '/',
    method: eventData.method || 'GET',
    ruleTriggered: eventData.ruleTriggered || 'GENERAL_INSPECTION',
    actionTaken: eventData.actionTaken || 'ALLOWED',
    payloadSample: (eventData.payloadSample || '').substring(0, 300),
    geo: eventData.geo || 'Local Security Zone (Apex Campus Network)'
  };

  // Add to in-memory circular buffer (keeps last 500 events)
  dbState.security_logs.unshift(entry);
  if (dbState.security_logs.length > 500) {
    dbState.security_logs.pop();
  }

  // Append to disk audit log
  appendAuditLog(entry);

  // Broadcast to all active SOC SSE subscribers
  broadcastToSoc(entry);

  return entry;
}

function getSecurityLogs(limit = 50, offset = 0, severityFilter = null) {
  let logs = dbState.security_logs;
  if (severityFilter) {
    logs = logs.filter(l => l.severity === severityFilter);
  }
  return {
    total: logs.length,
    logs: logs.slice(offset, offset + limit)
  };
}

// -----------------------------------------------------------------------------
// METRICS & TELEMETRY
// -----------------------------------------------------------------------------

function incrementMetric(metricName, count = 1) {
  if (dbState.metrics[metricName] !== undefined) {
    dbState.metrics[metricName] += count;
  }
}

function getMetrics() {
  updateActiveLockoutMetrics();
  return {
    ...dbState.metrics,
    currentTime: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime())
  };
}

// -----------------------------------------------------------------------------
// SOC REAL-TIME EVENT STREAMING (SSE BUS)
// -----------------------------------------------------------------------------

function registerSocSubscriber(res) {
  socSubscribers.add(res);
}

function removeSocSubscriber(res) {
  socSubscribers.delete(res);
}

function broadcastToSoc(eventEntry) {
  const payload = `data: ${JSON.stringify(eventEntry)}\n\n`;
  for (const client of socSubscribers) {
    try {
      client.write(payload);
    } catch (err) {
      socSubscribers.delete(client);
    }
  }
}

// Initialize on module load
initializeDatabase();

module.exports = {
  getUserByEmail,
  getUserById,
  getAllUsersSanitized,
  recordFailedAttempt,
  getFailedAttempts,
  resetFailedAttempts,
  recordLockout,
  getActiveLockout,
  overrideLockouts,
  getAllLockouts,
  logSecurityEvent,
  getSecurityLogs,
  incrementMetric,
  getMetrics,
  registerSocSubscriber,
  removeSocSubscriber,
  formatDuration,
  SEED_USERS
};
