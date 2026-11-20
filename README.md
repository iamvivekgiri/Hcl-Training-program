# WebShield: Multi-Layer Web Access & Intrusion Protection System
**Protecting Apex Institute of Technology & Cyber Sciences**

WebShield is a production-grade, multi-layer security suite (WAF + IAM + IDS) protecting an interactive 3D WebGL university portal. It enforces hardware-based client fingerprinting, a strict 3-strike 24-hour lockout engine, sliding-window rate limiting, and real-time deep-packet intrusion detection.

---

## 🏛️ Architecture & Defense Layers

1. **Layer 1: Network Perimeter & Rate-Limiting Gate**
   - Sliding-window rate limiter: **Max 30 requests/minute** per IP + fingerprint (`HTTP 429` with `Retry-After`).
   - Hardware-bound Composite Client Fingerprint (`HMAC-SHA256(Canvas + WebGL + UserAgent + IP + Hardware + Screen)`).
   - Clearing browser cookies alone cannot bypass an active lockout.

2. **Layer 2: Multi-Layer Authentication & 3-Strike 24-Hour Lockout Engine**
   - **Attempt 1 Failed:** Decrements attempts to `2`, logs `WARN_AUTH_FAIL`, triggers subtle amber shield pulse.
   - **Attempt 2 Failed:** Decrements attempts to `1`, issues dynamic HMAC challenge token, logs `HIGH_AUTH_FAIL`.
   - **Attempt 3 Failed:** Triggers **CRITICAL_LOCKOUT** for exactly **24 hours (86,400,000 ms)** with `HTTP 423 Locked`.
   - **During 24-Hour Lockout:** Precision real-time `HH:MM:SS` countdown timer, Threat ID, and forensic receipt. Persists across browser refreshes and server reboots.
   - **Evaluator Fast-Forward:** Master unlock key `SOC-RESET-2026` unlocks accounts instantly during live demonstrations.

3. **Layer 3: Deep Packet / Payload Intrusion Detection (WAF & IDS)**
   - Scans queries, bodies, and headers against heuristic signatures for:
     - **SQL Injection (SQLi):** `' OR 1=1`, `UNION SELECT`, `DROP TABLE`, comments (`--`, `;--`), blind timing (`sleep()`, `benchmark()`).
     - **Cross-Site Scripting (XSS):** `<script>`, inline event handlers (`onerror=`, `onload=`), `javascript:`, DOM execution sinks.
     - **Path Traversal & Command Injection:** `../`, `/etc/passwd`, `win.ini`, `&& cat`, `| bash`, Log4j JNDI.
   - Intercepts malicious payloads immediately (`HTTP 403 Forbidden`), increments Global Threat Counter, logs forensic telemetry, and triggers a 3D red deflection wave.

4. **Layer 4: Session Hardening & Gatekeeper**
   - Issues signed `HttpOnly`, `SameSite=Strict` JWT session tokens.
   - Unauthenticated visitors attempting to fetch internal portal routes (`/portal`, `/academics`, `/admissions`, `/faculty`, `/research`) are strictly redirected to `/`.

---

## 🚀 Quickstart & Setup

### 1. Install Dependencies
```bash
cd C:\Users\vivek\.gemini\antigravity\scratch\webshield
npm install
```

### 2. Start WebShield Server
```bash
npm start
```
The server will start at: **http://localhost:3000**

---

## 🔑 Pre-Seeded Demonstration Accounts

| Role | Email | Password | Clearance & Purpose |
| :--- | :--- | :--- | :--- |
| **Student** | `student@apex.edu` | `Apex@2026` | Level 1: Cyber Defense & Quantum Computing |
| **Faculty** | `faculty@apex.edu` | `CyberProf#99` | Level 3: Autonomous Systems & AI Security |
| **SOC Admin** | `admin@apex.edu` | `ShieldMaster!01` | Level 5: Threat Intelligence & Global Perimeter Control |
| **Evaluator Override** | — | `SOC-RESET-2026` | Fast-forward key to reset 24-hour lockout during demo |

---

## 🧪 Live Attack Simulation Guide

The login gate includes a dedicated **Live Attack Simulation bar**:
1. **SQLi Attack (`' OR 1=1; DROP TABLE users;--`):** Demonstrates immediate WAF packet dropping (`HTTP 403`) and 3D red deflection shockwave.
2. **XSS Injection (`<script>...</script>`):** Shows cross-site scripting heuristic interception.
3. **Path Traversal (`../../../../etc/passwd`):** Demonstrates sensitive system file access blocking.
4. **Fast-Trigger 3-Strike Lockout:** Simulates rapid brute-force credential failure to immediately showcase the 24-hour countdown screen, forensic receipt, and evaluator override modal.
