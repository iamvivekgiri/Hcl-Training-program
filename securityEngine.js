/**
 * WebShield Multi-Layer Web Access & Intrusion Protection System
 * Layer 1 (Perimeter & Rate Gate) + Layer 2 (IAM & 3-Strike 24h Lockout) + Layer 3 (WAF & IDS)
 * Apex Institute of Technology & Cyber Sciences
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./database');

// Secret keys for cryptographic tokens & session signing
const JWT_SECRET = process.env.JWT_SECRET || 'ApexInstitute_WebShield_Core_Key_2026_SecureHmac';
const CHALLENGE_SECRET = process.env.CHALLENGE_SECRET || 'Apex_DynamicChallenge_HMAC_Secret_99';
const FINGERPRINT_SALT = process.env.FINGERPRINT_SALT || 'Apex_Canvas_WebGL_Salt_2026';

// Engineering constants
const LOCKOUT_DURATION_MS = 24 * 60 * 60 * 1000; // Exact 24 Hours: 86,400,000 ms
const MAX_STRIKES_BEFORE_LOCKOUT = 3;
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute sliding window
const RATE_LIMIT_MAX_REQUESTS = 30; // Max 30 requests/minute per IP/fingerprint
const ADMIN_OVERRIDE_KEY = 'SOC-RESET-2026'; // Evaluator fast-forward key

// In-Memory Sliding-Window Rate Limit Cache
// Key: composite IP:Fingerprint, Value: Array of request timestamps
const rateLimitLog = new Map();

// -----------------------------------------------------------------------------
// LAYER 1: NETWORK PERIMETER & RATE-LIMITING GATE
// -----------------------------------------------------------------------------

/**
 * Robust Client IP Extraction (handles reverse proxies, CF, x-forwarded-for)
 */
function extractClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(ip => ip.trim());
    if (ips[0]) return ips[0];
  }
  return req.headers['x-real-ip'] ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         req.ip ||
         '127.0.0.1';
}

/**
 * Generate Persistent Composite Client Device Fingerprint
 * Combines Canvas + WebGL + UserAgent + IP Hash
 */
function generateCompositeFingerprint(req, clientProvidedFp = null) {
  const ip = extractClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown-UserAgent';
  const acceptLang = req.headers['accept-language'] || '';
  const secChUa = req.headers['sec-ch-ua'] || '';

  // If client sent client-side hardware telemetry (Canvas/WebGL/Screen/Hardware)
  let rawComponents;
  if (clientProvidedFp && typeof clientProvidedFp === 'object') {
    rawComponents = [
      clientProvidedFp.canvasHash || 'no-canvas',
      clientProvidedFp.webglVendor || 'no-webgl-v',
      clientProvidedFp.webglRenderer || 'no-webgl-r',
      clientProvidedFp.screenRes || 'no-screen',
      clientProvidedFp.hardwareConcurrency || 'no-hw',
      clientProvidedFp.timezone || 'no-tz',
      userAgent,
      ip
    ].join('###');
  } else if (typeof clientProvidedFp === 'string' && clientProvidedFp.length >= 16) {
    rawComponents = `${clientProvidedFp}###${userAgent}###${ip}`;
  } else {
    // Server-side fallback composite fingerprint
    rawComponents = `${userAgent}###${acceptLang}###${secChUa}###${ip}`;
  }

  return crypto.createHmac('sha256', FINGERPRINT_SALT)
               .update(rawComponents)
               .digest('hex');
}

/**
 * Sliding-Window Rate Limiter Middleware
 * Max 30 requests/minute per IP/Device Fingerprint
 */
function rateLimiterMiddleware(req, res, next) {
  const ip = extractClientIp(req);
  const clientFpHeader = req.headers['x-webshield-fingerprint'] || req.cookies?.webshield_fp;
  const fingerprint = generateCompositeFingerprint(req, clientFpHeader);
  const rateKey = `${ip}::${fingerprint}`;
  const now = Date.now();

  // Retrieve sliding window log for this identity
  let timestamps = rateLimitLog.get(rateKey) || [];

  // Evict timestamps older than 60 seconds
  const windowStart = now - RATE_LIMIT_WINDOW_MS;
  timestamps = timestamps.filter(ts => ts > windowStart);

  if (timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    db.incrementMetric('rateLimitBlocks');
    db.incrementMetric('totalThreatsBlocked');

    db.logSecurityEvent({
      eventType: 'RATE_LIMIT_EXCEEDED',
      severity: 'HIGH',
      ip,
      fingerprint,
      endpoint: req.originalUrl || req.url,
      method: req.method,
      ruleTriggered: 'LAYER1_SLIDING_WINDOW_BURST',
      actionTaken: 'BLOCKED_429',
      payloadSample: `Rate Limit Exceeded: ${timestamps.length} reqs in past 60s (Threshold: ${RATE_LIMIT_MAX_REQUESTS})`
    });

    const retryAfter = Math.ceil((timestamps[0] + RATE_LIMIT_WINDOW_MS - now) / 1000);
    res.setHeader('Retry-After', Math.max(1, retryAfter));
    res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX_REQUESTS);
    res.setHeader('X-RateLimit-Remaining', 0);
    res.setHeader('X-RateLimit-Reset', Math.ceil((now + RATE_LIMIT_WINDOW_MS) / 1000));

    return res.status(429).json({
      error: 'HTTP Flood / Rate Limit Exceeded: WebShield Network Perimeter Gate Active',
      status: 'BLOCKED_429',
      limit: RATE_LIMIT_MAX_REQUESTS,
      windowSeconds: 60,
      retryAfterSeconds: Math.max(1, retryAfter),
      fingerprint,
      shieldState: 'CRIMSON_LOCKOUT',
      threatAlert: 'Burst attack pattern detected. Access suspended by perimeter rate limiter.'
    });
  }

  // Record current request timestamp
  timestamps.push(now);
  rateLimitLog.set(rateKey, timestamps);

  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX_REQUESTS);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT_MAX_REQUESTS - timestamps.length));

  next();
}

// -----------------------------------------------------------------------------
// LAYER 3: DEEP PACKET / PAYLOAD INTRUSION DETECTION (WAF & IDS)
// -----------------------------------------------------------------------------

/**
 * Enterprise Signature Matrix for SQLi, XSS, and Path Traversal / Command Injection
 */
const WAF_SIGNATURE_SETS = [
  // 1. SQL INJECTION (SQLi)
  {
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'SQLi_Tautology_Boolean',
    pattern: /(?:'|"|%27|%22)\s*(?:or|and|xor|rlike|not)\s*(?:['"0-9a-zA-Z]+|\d+)\s*=\s*(?:['"0-9a-zA-Z]+|\d+)/i
  },
  {
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'SQLi_Union_Select',
    pattern: /\bunion\b\s+(?:\ball\b\s+)?\bselect\b/i
  },
  {
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'SQLi_Destructive_DML_DDL',
    pattern: /;\s*(?:drop|truncate|alter|delete\s+from|insert\s+into|update\s+\w+\s+set)\b/i
  },
  {
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    ruleName: 'SQLi_Comment_Truncation',
    pattern: /(?:--|#|;--|;\s*--|\/\*[\s\S]*?\*\/)/
  },
  {
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'SQLi_System_Functions_Blind',
    pattern: /\b(?:xp_cmdshell|sp_executesql|benchmark\s*\(|pg_sleep\s*\(|sleep\s*\(|waitfor\s+delay)\b/i
  },
  {
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    ruleName: 'SQLi_Information_Schema_Enumeration',
    pattern: /\b(?:information_schema|sys\.databases|sqlite_master|all_tables)\b/i
  },

  // 2. CROSS-SITE SCRIPTING (XSS)
  {
    category: 'XSS_ATTACK',
    severity: 'HIGH',
    ruleName: 'XSS_Explicit_Script_Tag',
    pattern: /<\s*script\b[^>]*>[\s\S]*?<\s*\/\s*script\s*>|<\s*script\b/i
  },
  {
    category: 'XSS_ATTACK',
    severity: 'HIGH',
    ruleName: 'XSS_Inline_EventHandler',
    pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|keydown|keyup|change|mouseenter)\s*=/i
  },
  {
    category: 'XSS_ATTACK',
    severity: 'HIGH',
    ruleName: 'XSS_Pseudo_Protocol',
    pattern: /(?:javascript|vbscript|data\s*:\s*text\/html)\s*:/i
  },
  {
    category: 'XSS_ATTACK',
    severity: 'HIGH',
    ruleName: 'XSS_DOM_Execution_Sink',
    pattern: /\b(?:document\.(?:cookie|location|write)|window\.location|eval\s*\(|new\s+Function\s*\()/i
  },
  {
    category: 'XSS_ATTACK',
    severity: 'HIGH',
    ruleName: 'XSS_Vector_Elements',
    pattern: /<\s*(?:iframe|object|embed|svg|img|link|meta)\b[^>]*?(?:src|href|onload|onerror|data)\s*=/i
  },

  // 3. PATH TRAVERSAL & REMOTE COMMAND INJECTION
  {
    category: 'PATH_TRAVERSAL',
    severity: 'CRITICAL',
    ruleName: 'Path_Directory_Traversal',
    pattern: /(?:\.\.[\/\\]|\.\.%2f|\.\.%5c|\%2e\%2e[\/\\])/i
  },
  {
    category: 'PATH_TRAVERSAL',
    severity: 'CRITICAL',
    ruleName: 'Path_Sensitive_File_Probe',
    pattern: /(?:\/etc\/(?:passwd|shadow|hosts|group|issue))|(?:c:[\\\/]windows[\\\/]system32)|(?:win\.ini)/i
  },
  {
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'Cmd_Shell_Chaining',
    pattern: /(?:&&|\|\||;|\`|\$\()\s*(?:cat|ls|pwd|whoami|bash|sh|cmd|powershell|curl|wget|nc|netcat|rm|kill|chmod)\b/i
  },
  {
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    ruleName: 'Cmd_Pipe_Execution',
    pattern: /(?:\|\s*bash|\|\s*sh|>\s*\/dev\/null)/i
  },
  {
    category: 'REMOTE_EXPLOIT',
    severity: 'CRITICAL',
    ruleName: 'Log4j_JNDI_Exploit',
    pattern: /\$\{jndi:(?:ldap|rmi|dns|nis):/i
  }
];

/**
 * Deep recursive string scanner for nested JSON / URL objects
 */
function scanPayloadRecursively(value, matches = []) {
  if (value === null || value === undefined) return matches;

  if (typeof value === 'string') {
    const decodedValue = safeUrlDecode(value);
    for (const sig of WAF_SIGNATURE_SETS) {
      if (sig.pattern.test(value) || sig.pattern.test(decodedValue)) {
        matches.push({
          category: sig.category,
          severity: sig.severity,
          ruleName: sig.ruleName,
          matchedSample: value.substring(0, 150)
        });
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) {
      scanPayloadRecursively(item, matches);
    }
  } else if (typeof value === 'object') {
    for (const key of Object.keys(value)) {
      // Also inspect keys for parameter pollution attacks
      scanPayloadRecursively(key, matches);
      scanPayloadRecursively(value[key], matches);
    }
  }

  return matches;
}

function safeUrlDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch (e) {
    return str;
  }
}

/**
 * Deep Packet Inspection (WAF & IDS) Middleware
 * Inspects Query, Body, Headers (referer, custom tokens)
 */
function wafInspectionMiddleware(req, res, next) {
  db.incrementMetric('totalRequestsInspected');

  const ip = extractClientIp(req);
  const clientFpHeader = req.headers['x-webshield-fingerprint'] || req.cookies?.webshield_fp;
  const fingerprint = generateCompositeFingerprint(req, clientFpHeader);

  const matchedThreats = [];

  // 1. Inspect Query Parameters
  if (req.query && Object.keys(req.query).length > 0) {
    scanPayloadRecursively(req.query, matchedThreats);
  }

  // 2. Inspect Request Body
  if (req.body && Object.keys(req.body).length > 0) {
    scanPayloadRecursively(req.body, matchedThreats);
  }

  // 3. Inspect Specific Headers that could carry payloads (Referer, User-Agent, X-Custom)
  const suspiciousHeaders = ['referer', 'user-agent', 'x-forwarded-host', 'x-attack-vector'];
  for (const h of suspiciousHeaders) {
    if (req.headers[h]) {
      scanPayloadRecursively(req.headers[h], matchedThreats);
    }
  }

  // If any threat signature detected -> Instant Intrusion Block
  if (matchedThreats.length > 0) {
    const primaryThreat = matchedThreats[0];
    db.incrementMetric('totalThreatsBlocked');

    if (primaryThreat.category === 'SQL_INJECTION') db.incrementMetric('sqliDeflected');
    if (primaryThreat.category === 'XSS_ATTACK') db.incrementMetric('xssDeflected');
    if (primaryThreat.category === 'PATH_TRAVERSAL' || primaryThreat.category === 'COMMAND_INJECTION') {
      db.incrementMetric('traversalDeflected');
    }

    const threatId = `THREAT-IDS-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    // Log forensic telemetry
    const logEntry = db.logSecurityEvent({
      eventType: `INTRUSION_DETECTED_${primaryThreat.category}`,
      severity: primaryThreat.severity,
      ip,
      fingerprint,
      endpoint: req.originalUrl || req.url,
      method: req.method,
      ruleTriggered: primaryThreat.ruleName,
      actionTaken: 'INSTANT_INTRUSION_BLOCK_403',
      payloadSample: `[${primaryThreat.ruleName}] Sample: ${primaryThreat.matchedSample}`,
      threatId
    });

    return res.status(403).json({
      error: 'WebShield Intrusion Detection System: Malicious Payload Intercepted & Blocked',
      status: 'INTRUSION_DEFLECTED',
      statusCode: 403,
      threatId,
      category: primaryThreat.category,
      ruleName: primaryThreat.ruleName,
      severity: primaryThreat.severity,
      sampleSnippet: primaryThreat.matchedSample,
      clientIp: ip,
      clientFingerprint: fingerprint,
      timestamp: logEntry.timestamp,
      shieldState: 'CRIMSON_LOCKOUT',
      shieldDeflection: true,
      message: 'Packet dropped by Deep Packet Inspection WAF. Incident forensic telemetry logged.'
    });
  }

  // Continue to next security filter
  next();
}

// -----------------------------------------------------------------------------
// LAYER 2: MULTI-LAYER AUTHENTICATION & 3-STRIKE 24-HOUR LOCKOUT ENGINE
// -----------------------------------------------------------------------------

/**
 * Generate Dynamic Security Challenge Token for Strike 2
 */
function generateChallengeToken(username, fingerprint) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  const payload = `${username}::${fingerprint}::${timestamp}::${nonce}`;
  const signature = crypto.createHmac('sha256', CHALLENGE_SECRET).update(payload).digest('hex');

  // Human-solvable arithmetic puzzle for extra validation demonstration
  const num1 = Math.floor(Math.random() * 8) + 2;
  const num2 = Math.floor(Math.random() * 8) + 2;
  const expectedAnswer = num1 + num2;
  const answerHash = crypto.createHmac('sha256', CHALLENGE_SECRET).update(`${expectedAnswer}::${nonce}`).digest('hex');

  return {
    challengeToken: `${payload}::${signature}`,
    question: `WebShield Identity Verification Challenge: What is ${num1} + ${num2}?`,
    nonce,
    answerHash
  };
}

/**
 * Validate Dynamic Challenge Token & Solution
 */
function verifyChallengeToken(tokenString, userAnswer, answerHash, nonce) {
  if (!tokenString) return false;
  try {
    const parts = tokenString.split('::');
    if (parts.length !== 5) return false;
    const [user, fp, ts, parsedNonce, signature] = parts;

    // Check expiration (valid for 5 minutes)
    if (Date.now() - parseInt(ts, 10) > 5 * 60 * 1000) {
      return false;
    }

    const testPayload = `${user}::${fp}::${ts}::${parsedNonce}`;
    const expectedSig = crypto.createHmac('sha256', CHALLENGE_SECRET).update(testPayload).digest('hex');
    if (signature !== expectedSig) return false;

    // Validate arithmetic response
    if (userAnswer !== undefined && answerHash && nonce) {
      const computedHash = crypto.createHmac('sha256', CHALLENGE_SECRET)
                                 .update(`${userAnswer.toString().trim()}::${nonce}`)
                                 .digest('hex');
      if (computedHash !== answerHash) {
        return false;
      }
    }

    return true;
  } catch (err) {
    return false;
  }
}

/**
 * 24-Hour Lockout Enforcement Middleware
 * Intercepts every request to authentication routes & internal routes
 */
function checkLockoutMiddleware(req, res, next) {
  const ip = extractClientIp(req);
  const clientFpHeader = req.headers['x-webshield-fingerprint'] || req.cookies?.webshield_fp;
  const fingerprint = generateCompositeFingerprint(req, clientFpHeader);
  const username = req.body?.username || req.query?.username || null;

  const activeLockout = db.getActiveLockout(username, fingerprint, ip);

  if (activeLockout) {
    return res.status(423).json({
      error: 'CRITICAL SECURITY LOCKOUT ACTIVATED: 24-Hour Access Restriction Enforced',
      status: 'CRITICAL_LOCKOUT_423',
      statusCode: 423,
      threatId: activeLockout.threatId,
      username: activeLockout.username,
      fingerprint: activeLockout.fingerprint,
      ip: activeLockout.ip,
      lockedAt: new Date(activeLockout.lockedAt).toISOString(),
      expiresAt: new Date(activeLockout.expiresAt).toISOString(),
      remainingMs: activeLockout.remainingMs,
      remainingFormatted: activeLockout.remainingFormatted,
      reason: activeLockout.reason,
      shieldState: 'CRIMSON_LOCKOUT',
      overrideAvailable: true,
      message: '3-Strike credential failure threshold breached. System access locked for exactly 24 hours.'
    });
  }

  // Attach resolved fingerprint and IP to request object for downstream handlers
  req.clientIp = ip;
  req.clientFingerprint = fingerprint;

  next();
}

/**
 * Process Authentication Login Attempt with 3-Strike 24-Hour Logic
 */
async function processLoginAttempt({ username, password, clientFingerprint, ip, challengeToken, challengeAnswer, challengeAnswerHash, challengeNonce }) {
  if (!username || !password) {
    return {
      success: false,
      statusCode: 400,
      message: 'Username and password credentials are required.'
    };
  }

  // 1. Check if user/device is already locked out
  const activeLockout = db.getActiveLockout(username, clientFingerprint, ip);
  if (activeLockout) {
    return {
      success: false,
      statusCode: 423,
      lockoutActive: true,
      lockoutData: activeLockout
    };
  }

  // 2. Fetch existing failed attempts count
  const existingFailures = db.getFailedAttempts(username, clientFingerprint, ip);

  // If on Strike 2 (already failed 2 times, this is attempt 3), verify Dynamic Security Challenge
  if (existingFailures.count === 2) {
    const isChallengeValid = verifyChallengeToken(
      challengeToken,
      challengeAnswer,
      challengeAnswerHash,
      challengeNonce
    );

    if (!isChallengeValid) {
      // Failed challenge counts as third strike -> Trigger 24-Hour Lockout!
      const lockoutRecord = db.recordLockout(
        username,
        clientFingerprint,
        ip,
        'Attempt 3: Failed Dynamic Security Challenge and Authentication'
      );

      return {
        success: false,
        statusCode: 423,
        lockoutActive: true,
        threatId: lockoutRecord.threatId,
        remainingMs: lockoutRecord.durationMs,
        remainingFormatted: db.formatDuration(lockoutRecord.durationMs),
        shieldState: 'CRIMSON_LOCKOUT',
        message: 'Security Challenge Failed. 3-Strike Threshold reached. 24-Hour Lockout Activated!'
      };
    }
  }

  // 3. Validate user credentials against persistent database
  const user = db.getUserByEmail(username);
  let credentialsValid = false;

  if (user) {
    const bcrypt = require('bcryptjs');
    credentialsValid = bcrypt.compareSync(password, user.passwordHash);
  }

  // 4. Handle Valid Credentials
  if (credentialsValid) {
    // Reset failed strikes upon successful authentication
    db.resetFailedAttempts(username, clientFingerprint, ip);
    db.incrementMetric('totalAuthSuccesses');

    // Issue signed JWT token
    const token = issueSessionToken(user, clientFingerprint);

    db.logSecurityEvent({
      eventType: 'AUTH_SUCCESS',
      severity: 'INFO',
      ip,
      fingerprint: clientFingerprint,
      username: user.email,
      endpoint: '/api/auth/login',
      method: 'POST',
      ruleTriggered: 'IAM_CREDENTIAL_VERIFIED',
      actionTaken: 'ALLOWED_SESSION_ISSUED',
      payloadSample: `User ${user.email} authenticated successfully. Role: ${user.role}`
    });

    return {
      success: true,
      statusCode: 200,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
        clearanceLevel: user.clearanceLevel,
        avatar: user.avatar
      },
      token,
      shieldState: 'EMERALD_VERIFIED',
      message: 'Identity Verified — Decrypting Campus Portal'
    };
  }

  // 5. Handle Failed Credential Attempt (Increment Strikes)
  const updatedFailures = db.recordFailedAttempt(username, clientFingerprint, ip);
  const currentStrike = updatedFailures.count;
  const attemptsRemaining = Math.max(0, MAX_STRIKES_BEFORE_LOCKOUT - currentStrike);

  // -------------------------------------------------------------
  // ATTEMPT 1 FAILED
  // -------------------------------------------------------------
  if (currentStrike === 1) {
    db.logSecurityEvent({
      eventType: 'WARN_AUTH_FAIL',
      severity: 'WARN',
      ip,
      fingerprint: clientFingerprint,
      username,
      endpoint: '/api/auth/login',
      method: 'POST',
      ruleTriggered: 'LAYER2_AUTH_STRIKE_1',
      actionTaken: 'FLAGGED_ATTEMPT_1',
      payloadSample: `Invalid credentials for ${username}. Remaining attempts: 2.`
    });

    return {
      success: false,
      statusCode: 401,
      strike: 1,
      attemptsRemaining: 2,
      shieldState: 'AMBER_PULSE',
      message: 'Invalid credentials. Warning: 2 attempts remaining before 24-hour lockout.'
    };
  }

  // -------------------------------------------------------------
  // ATTEMPT 2 FAILED: REQUIRE DYNAMIC SECURITY CHALLENGE
  // -------------------------------------------------------------
  if (currentStrike === 2) {
    const challenge = generateChallengeToken(username, clientFingerprint);

    db.logSecurityEvent({
      eventType: 'HIGH_AUTH_FAIL',
      severity: 'HIGH',
      ip,
      fingerprint: clientFingerprint,
      username,
      endpoint: '/api/auth/login',
      method: 'POST',
      ruleTriggered: 'LAYER2_AUTH_STRIKE_2_CHALLENGE_ISSUED',
      actionTaken: 'CHALLENGED_ATTEMPT_2',
      payloadSample: `High risk for ${username}. Issued Dynamic HMAC challenge. Remaining attempts: 1.`
    });

    return {
      success: false,
      statusCode: 401,
      strike: 2,
      attemptsRemaining: 1,
      shieldState: 'SOLAR_WARNING',
      challengeRequired: true,
      challengeToken: challenge.challengeToken,
      challengeQuestion: challenge.question,
      challengeNonce: challenge.nonce,
      challengeAnswerHash: challenge.answerHash,
      message: 'Second consecutive failed login. High threat alert: 1 attempt remaining. Complete security challenge.'
    };
  }

  // -------------------------------------------------------------
  // ATTEMPT 3 FAILED: TRIGGER 24-HOUR CRITICAL LOCKOUT!
  // -------------------------------------------------------------
  const lockoutRecord = db.recordLockout(
    username,
    clientFingerprint,
    ip,
    '3 Consecutive Authentication Failures Exceeded Maximum Allowed Threshold'
  );

  return {
    success: false,
    statusCode: 423,
    strike: 3,
    attemptsRemaining: 0,
    lockoutActive: true,
    threatId: lockoutRecord.threatId,
    username: lockoutRecord.username,
    fingerprint: lockoutRecord.fingerprint,
    ip: lockoutRecord.ip,
    lockedAt: new Date(lockoutRecord.lockedAt).toISOString(),
    expiresAt: new Date(lockoutRecord.expiresAt).toISOString(),
    remainingMs: lockoutRecord.durationMs,
    remainingFormatted: db.formatDuration(lockoutRecord.durationMs),
    shieldState: 'CRIMSON_LOCKOUT',
    message: 'CRITICAL 3-STRIKE BREACH: 24-Hour Access Lockout Activated!'
  };
}

// -----------------------------------------------------------------------------
// LAYER 4: SESSION HARDENING & GATEKEEPER AUTHORIZATION
// -----------------------------------------------------------------------------

/**
 * Issue Signed HttpOnly JWT Session Token
 */
function issueSessionToken(user, clientFingerprint) {
  const payload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    department: user.department,
    clearanceLevel: user.clearanceLevel,
    fpHash: clientFingerprint.substring(0, 16),
    iat: Math.floor(Date.now() / 1000)
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '8h',
    algorithm: 'HS256'
  });
}

/**
 * Verify Session JWT Token
 */
function verifySessionToken(token) {
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return null;
  }
}

/**
 * Protected Route Gatekeeper Middleware
 * Unauthenticated requests to internal portal routes redirect immediately to WebShield Gate
 */
function requireAuth(req, res, next) {
  const token = req.cookies?.webshield_session ||
                (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
                  ? req.headers.authorization.substring(7)
                  : null);

  const decoded = verifySessionToken(token);

  if (!decoded) {
    // If request accepts HTML (direct browser navigation), redirect to security gatekeeper
    if (req.accepts('html')) {
      return res.redirect('/?denied=unauthenticated&ref=' + encodeURIComponent(req.originalUrl || req.url));
    }

    return res.status(401).json({
      error: 'WebShield IAM Gatekeeper: Unauthenticated Access Denied',
      status: 'UNAUTHORIZED_401',
      shieldState: 'AMBER_PULSE',
      redirect: '/'
    });
  }

  req.user = decoded;
  next();
}

/**
 * Role-Based Access Control (RBAC) Middleware
 */
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      db.logSecurityEvent({
        eventType: 'ACCESS_DENIED_RBAC',
        severity: 'WARN',
        ip: extractClientIp(req),
        fingerprint: req.clientFingerprint || 'unknown-fp',
        username: req.user.email,
        endpoint: req.originalUrl,
        method: req.method,
        ruleTriggered: 'RBAC_PERMISSION_CHECK',
        actionTaken: 'BLOCKED_403',
        payloadSample: `User role '${req.user.role}' lacks clearance for '${allowedRoles.join(',')}'`
      });

      return res.status(403).json({
        error: 'Forbidden: Insufficient Security Clearance',
        requiredRoles: allowedRoles,
        userRole: req.user.role
      });
    }

    next();
  };
}

module.exports = {
  extractClientIp,
  generateCompositeFingerprint,
  rateLimiterMiddleware,
  wafInspectionMiddleware,
  checkLockoutMiddleware,
  processLoginAttempt,
  issueSessionToken,
  verifySessionToken,
  requireAuth,
  requireRole,
  ADMIN_OVERRIDE_KEY,
  LOCKOUT_DURATION_MS
};
