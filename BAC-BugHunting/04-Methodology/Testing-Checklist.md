---
tags: [bac, methodology, checklist, testing]
type: methodology
date: 2026-03-10
---

# ✅ BAC Master Testing Checklist — v3

> **How to use**: Copy this to `09-Targets/` for each new program. Check off as you go. The Tasks plugin will surface open items in the Dashboard automatically.

---

## 🔵 Phase 1: Reconnaissance & Setup

### Account Setup
- [ ] #task Attacker account created (low-privilege user)
- [ ] #task Victim account created (same role as attacker — different user)
- [ ] #task Admin account obtained (self-register, or request from program)
- [ ] #task Guest / unauthenticated session noted (no cookie baseline)

### Endpoint Mapping
- [ ] #task All JS files downloaded and parsed for hidden API endpoints
- [ ] #task Swagger / OpenAPI documentation discovered and downloaded
- [ ] #task Wayback Machine / GAU historical endpoint enumeration complete
- [ ] #task GitHub / GitLab recon done for codebase API routes
- [ ] #task Mobile APK decompiled and API routes extracted (if applicable)
- [ ] #task Postman public workspace searched for target collections

### Object ID Collection (for IDOR testing)
- [ ] #task Victim's order IDs collected
- [ ] #task Victim's file / document IDs collected
- [ ] #task Victim's invoice / payment IDs collected
- [ ] #task Victim's message / notification IDs collected
- [ ] #task Victim's project / workspace IDs collected
- [ ] #task Victim's user ID noted (from /api/me or profile response)

### Role & Permission Matrix
- [ ] #task All roles mapped (guest, user, premium, moderator, admin, etc.)
- [ ] #task Expected permissions documented per role per resource
- [ ] #task Undocumented / internal roles searched for in JS files

---

## 🟡 Phase 2: IDOR & Object-Level Authorization

### Core IDOR
- [ ] #task Every endpoint accepting an object ID enumerated (Burp sitemap)
- [ ] #task Each endpoint tested with victim's IDs using attacker's session
- [ ] #task Each endpoint tested with no auth token (unauthenticated)
- [ ] #task Sequential integer IDs fuzzed (Intruder / ffuf / Turbo Intruder)
- [ ] #task UUID/GUID-based endpoints tested (GUIDs sourced from other API responses)
- [ ] #task Base64-encoded IDs decoded → modified → re-encoded → tested
- [ ] #task MD5/hash-based IDs: hash computed for target filename/value → tested

### IDOR via Parameter Location
- [ ] #task IDOR via URL path parameter (`/api/order/VICTIM_ID`)
- [ ] #task IDOR via query string (`?user_id=VICTIM_ID`, `?account=VICTIM_ID`)
- [ ] #task IDOR via JSON body (`{"user_id": VICTIM_ID}`)
- [ ] #task IDOR via HTTP request headers (`X-User-Id`, `X-Account-Id`, `X-Owner`)
- [ ] #task IDOR via cookies (role or ID baked into cookie value)
- [ ] #task IDOR via HTTP Parameter Pollution (`?id=MINE&id=VICTIM`)

### IDOR Scope Expansion
- [ ] #task Nested resource IDOR (`/users/VICTIM/orders`, `/orgs/VICTIM/members`)
- [ ] #task File download / export IDOR (`/download?file=`, `/export?report_id=`)
- [ ] #task Password reset / API key endpoints (`/users/VICTIM/reset-token`)
- [ ] #task Blind IDOR: write/delete actions checked for effect on victim's data
- [ ] #task Autorize plugin run across entire authenticated session

### API-Specific (BOLA / BFLA)
- [ ] #task BOLA: every REST object endpoint tested cross-account
- [ ] #task BFLA: admin functions called as low-priv user (all HTTP methods)
- [ ] #task GraphQL introspection query executed (try even if "disabled")
- [ ] #task GraphQL field-level auth: sensitive fields requested (passwordHash, apiKey, ssn)
- [ ] #task GraphQL mutations: ownership checked on all write operations
- [ ] #task GraphQL subscriptions: subscribe to another user's event channel
- [ ] #task GraphQL batch queries: used to enumerate IDs past rate limits
- [ ] #task Old API versions tested (v0, v1, beta, internal) for unpatched BOLA

---

## 🔴 Phase 3: Vertical Privilege Escalation

### Direct Admin Access
- [ ] #task All admin / internal paths probed unauthenticated
- [ ] #task All admin / internal paths probed as low-priv authenticated user
- [ ] #task Feroxbuster / ffuf run with AdminPanels.txt wordlist
- [ ] #task Setup / install / wizard endpoints checked (`/setup`, `/install`, `/admin/setup`)
- [ ] #task Debug endpoints checked (`/debug`, `/phpinfo.php`, `/server-status`)

### Header-Based Bypasses
- [ ] #task `X-Forwarded-For: 127.0.0.1` tested on all 403 responses
- [ ] #task `X-Real-IP: 127.0.0.1` tested
- [ ] #task `X-Original-URL: /admin/target` tested (nginx rewrite abuse)
- [ ] #task `X-Custom-IP-Authorization: 127.0.0.1` tested
- [ ] #task `X-Forwarded-Host: localhost` tested

### Path Normalization Bypasses
- [ ] #task `/ADMIN/path`, `/Admin/path` (case variants) tested
- [ ] #task `/admin//path`, `/admin/./path` (double-slash / dot) tested
- [ ] #task `/%61dmin/path` (URL-encoded char) tested
- [ ] #task `/admin;/path`, `/admin..;/path` (Spring Boot semicolon) tested
- [ ] #task `/api/../admin/path` (traversal resolving to admin) tested

### Role Injection
- [ ] #task Registration endpoint tested for role / isAdmin parameter injection
- [ ] #task All PUT / PATCH / POST endpoints tested for mass assignment
- [ ] #task Cookie role indicators tampered (`role=admin`, `isAdmin=true`)
- [ ] #task HTTP method abuse: all 8 methods tested on every protected endpoint
- [ ] #task Method override headers tested (`X-HTTP-Method-Override: DELETE`)

---

## 🟣 Phase 4: Token & Auth Bypass

### JWT Attacks
- [ ] #task All JWTs found (Authorization header, cookies, response bodies, localStorage)
- [ ] #task JWT decoded: all claims listed, `alg` and `kid` noted
- [ ] #task `alg: none` attack tested (jwt_tool `-X a`)
- [ ] #task RS256 → HS256 confusion tested if RS256 detected (jwt_tool `-X s`)
- [ ] #task HMAC secret brute-forced if HS256 (hashcat `-m 16500`)
- [ ] #task Role / admin / scope claims tampered and re-signed
- [ ] #task `kid` header: path traversal tested (`../../dev/null`)
- [ ] #task `kid` header: SQL injection tested (`x' UNION SELECT 'secret'--`)
- [ ] #task `jwk` header injection tested (embed attacker's public key)
- [ ] #task Token expiry: `exp` claim set to past date — still accepted?

### CORS
- [ ] #task Arbitrary origin reflected with `Access-Control-Allow-Credentials: true`?
- [ ] #task `null` origin reflected with credentials?
- [ ] #task Subdomain prefix (`target.com.evil.com`) reflected?
- [ ] #task Subdomain suffix (`eviltarget.com`) reflected?
- [ ] #task All sensitive API endpoints individually checked (not just homepage)

### OAuth 2.0 (if applicable)
- [ ] #task `redirect_uri` manipulated: full replace, subdomain spoof, path traversal
- [ ] #task `state` parameter removed — OAuth CSRF possible?
- [ ] #task Authorization code tested for reuse (replay after first exchange)
- [ ] #task Scope escalation tested in token request (add `admin:*` to scope)
- [ ] #task Token audience (`aud`) validated by resource server?
- [ ] #task PKCE: code exchanged without `code_verifier` — still works?
- [ ] #task Referer header checked for authorization code leakage

---

## ⚫ Phase 5: Forced Browsing & File Exposure

- [ ] #task Feroxbuster / ffuf run on all targets with common + admin wordlists
- [ ] #task Recursive directory scan run (`--depth 3`)
- [ ] #task Backup file extensions probed: `.bak`, `.old`, `.orig`, `~`, `.swp`
- [ ] #task `.git/` exposure checked (`/.git/HEAD`, `/.git/config`)
- [ ] #task `.env` / `.env.production` / `.env.local` checked
- [ ] #task `swagger.json`, `openapi.json`, `api-docs` probed on all subdomains
- [ ] #task Log file exposure checked (`/logs/`, `/error.log`, `/debug.log`)
- [ ] #task Predictable export / report URLs guessed from known patterns
- [ ] #task Old / versioned API paths probed (`/api/v0`, `/api/beta`, `/api/internal`)

---

## 🟢 Phase 6: Business Logic BAC

- [ ] #task All multi-step workflows mapped (checkout, onboarding, verification)
- [ ] #task Each final step accessed directly without completing prior steps
- [ ] #task Workflow steps reordered / replayed out of sequence
- [ ] #task Object states directly manipulated (`status: "paid"`, `verified: true`)
- [ ] #task `Referer` header spoofed to bypass referrer-gated actions
- [ ] #task Race conditions tested on critical state-change endpoints (50 concurrent)
- [ ] #task Invite / share links tested for missing identity binding
- [ ] #task Feature flags / beta params tested (`?beta=true`, `?internal=1`)
- [ ] #task Price / quantity parameters validated server-side? Test `"price": 0.01`

---

## 🔌 Phase 7: WebSocket BAC (if applicable)

- [ ] #task WebSocket traffic found and logged (DevTools → Network → WS)
- [ ] #task All WS messages with resource IDs identified
- [ ] #task Resource IDs in WS messages swapped for victim's IDs (IDOR)
- [ ] #task Subscription / join messages tested with other users' IDs
- [ ] #task Admin actions attempted via WS (less guarded than HTTP endpoints)
- [ ] #task WS handshake auth check: does connecting require valid session?
- [ ] #task WS messages from high-priv session replayed on low-priv connection

---

## 🔗 Phase 8: Advanced Chains

- [ ] #task Every IDOR checked for chain to password reset token → ATO
- [ ] #task CORS + IDOR chain attempted (CORS fetches IDOR-vulnerable endpoint)
- [ ] #task Mass assignment → admin capabilities → lateral movement explored
- [ ] #task Prototype pollution tested on Node.js targets (`__proto__`, `constructor.prototype`)
- [ ] #task `403` response bodies inspected for partial data leakage
- [ ] #task OAuth redirect_uri → subdomain takeover chain checked
- [ ] #task Request smuggling (CL.TE / TE.CL) attempted on proxy-fronted endpoints

---

## 📝 Phase 9: Reporting

- [ ] #task Clean HTTP request / response captured showing the access violation
- [ ] #task Two-account proof documented (attacker token + victim's resource = victim's data)
- [ ] #task Impact statement written in business terms (PII, financial, ATO potential)
- [ ] #task CVSS v3.1 vector calculated and scored
- [ ] #task Reproducible step-by-step PoC written
- [ ] #task Screenshots / video taken (request + response)
- [ ] #task Report drafted in [[Bug-Report-Template]]
- [ ] #task Report logged in [[Findings-Database]]
- [ ] #task Report submitted to program

---

## 🔗 Related Notes
- [[Recon-Phase]] | [[Reporting-BAC]] | [[Bug-Report-Template]]
- [[IDOR]] | [[Privilege-Escalation]] | [[Advanced-BAC-Chains]]
- [[WebSocket-BAC]] | [[OAuth-SSO-BAC]] | [[Forced-Browsing]]

---
*Tags: #checklist #methodology #bac #testing*

---

## 🔵 Phase 10: gRPC BAC (if applicable)

- [ ] #task Port scan for gRPC services (50051, 443, 8080, 9090, 9000)
- [ ] #task gRPC reflection tested: `grpcurl -plaintext target:50051 list`
- [ ] #task All services and methods enumerated from reflection
- [ ] #task Every method tested without auth credentials
- [ ] #task BOLA: user IDs swapped in gRPC requests
- [ ] #task Admin/privileged methods called from low-priv token
- [ ] #task Metadata injection tested (X-User-Role, X-Internal-User headers)
- [ ] #task gRPC-Web proxy: raw backend port tested separately for auth
- [ ] #task Protobuf field injection: is_admin, role added to request body

---

## ☁️ Phase 11: Cloud & Serverless BAC (if applicable)

- [ ] #task S3 buckets enumerated with domain name patterns (--no-sign-request)
- [ ] #task Lambda Function URLs discovered in JS/mobile and tested unauthenticated
- [ ] #task AWS API Gateway endpoints tested without auth and with expired credentials
- [ ] #task Cognito identity pool tested for unauthenticated credential grant
- [ ] #task GCP Cloud Functions / Cloud Run public endpoints discovered and tested
- [ ] #task Azure APIM: internal/health/metrics routes tested without subscription key
- [ ] #task SSRF payloads toward cloud IMDS (169.254.169.254 / metadata.google.internal)
- [ ] #task S3 bucket write access tested (upload test file --no-sign-request)
- [ ] #task CloudSploit / ScoutSuite run if cloud account credentials available
