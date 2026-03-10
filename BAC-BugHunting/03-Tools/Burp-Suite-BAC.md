---
tags: [bac, tools, burpsuite, proxy]
type: tools
date: 2026-03-10
---

# 🔧 Burp Suite — BAC Hunting Workflow

## Setup for BAC Testing

### 1. Project Configuration
```
Project Options → Sessions:
  - Add two session handling rules:
    Rule 1: "Attacker session" (your cookie)
    Rule 2: "Victim session" (victim's cookie)

Scope:
  - Add target domain
  - Enable passive scanning
  - Set filter: show in-scope only
```

### 2. Essential Extensions for BAC
```
BApp Store installs:
  ✅ Autorize          — Automated authorization testing
  ✅ AuthMatrix         — Multi-role testing matrix  
  ✅ JWT Editor         — JWT manipulation and attacks
  ✅ Param Miner        — Mass assignment discovery
  ✅ GAP               — JS endpoint extraction
  ✅403 Bypasser       — Path bypass automation
  ✅ Turbo Intruder    — High-speed IDOR fuzzing
  ✅ Logger++          — Advanced logging
```

---

## Autorize — Full Setup Guide
```
1. Login as VICTIM user, copy full Cookie header
2. Login as ATTACKER user in browser
3. Burp → Extender → Autorize
4. Paste victim's Cookie in "Cookie / Authorization Header value" box
5. Enable "Intercept requests from Repeater" ✅
6. Browse app as ATTACKER
7. Autorize replays every request with victim's cookie simultaneously
8. Color codes:
   🔴 Red (Bypassed): ATTACKER gets same response as VICTIM
   🟢 Green (Enforced): ATTACKER gets different/blocked response
   🟡 Yellow (Check): Similar length, review manually
9. Export report: right-click → Export to HTML
```

---

## AuthMatrix — Multi-Role Testing
```
Use case: Test 5 different roles against 50 endpoints simultaneously

Setup:
1. Configure users: Guest, User, Moderator, Admin, SuperAdmin
2. Provide session tokens for each role
3. Define expected access matrix (which roles should access what)
4. Run — it tests every endpoint with every role
5. Highlights unexpected access (e.g., Guest accessing Admin endpoint)
```

---

## Intruder for IDOR Scanning
```
1. Capture: GET /api/order/§1001§ HTTP/1.1
2. Send to Intruder → Sniper
3. Payloads → Numbers: From 1, To 10000, Step 1
4. Attack

Filtering results (Burp Pro):
- Add "Grep - Match" for common PII: email, phone, address, creditCard
- Filter by response length variation
- Filter out: 404, 400, 403 status codes

Turbo Intruder (faster):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)
    for i in range(1, 10000):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if req.status == 200 and len(req.response) > 200:
        table.add(req)
```

---

## Repeater Tips for BAC
```
1. Organize Repeater tabs by category:
   Tab name: "IDOR-orders", "ADMIN-bypass", "JWT-tamper"

2. Keyboard shortcuts:
   Ctrl+R: Send to Repeater
   Ctrl+Shift+R: Send and switch to Repeater
   
3. Compare responses:
   Right-click → Show response in browser
   Or: View → Comparer for side-by-side diff

4. Testing JWT:
   Headers tab → JSON Web Token (after JWT Editor install)
   Click "Alg: None attack" button
   Or manually edit payload claims
   Re-sign with "Sign" button
```

---

## Burp Scanner (Pro) — BAC Rules
```
Scan config → select:
  ✅ "Broken access control" 
  ✅ "IDOR"
  ✅ "Privilege escalation"

Active scan on:
  /api/* endpoints
  /admin/* endpoints
  /internal/* endpoints
```

---

## Custom Match-and-Replace Rules
```
For testing role-based access by modifying requests on-the-fly:

Proxy → Options → Match and Replace:
1. Replace "role":"user" with "role":"admin"
2. Replace "isAdmin":false with "isAdmin":true
3. Replace your user ID with a hardcoded victim ID
4. Add header: X-Forwarded-For: 127.0.0.1
```

---

## Tasks
- [ ] #task Install all 8 BApp extensions listed above
- [ ] #task Set up Autorize with victim's session token
- [ ] #task Configure AuthMatrix for all roles in target
- [ ] #task Set up Intruder template for IDOR scanning
- [ ] #task Create custom match-and-replace rules for role testing
- [ ] #task Set up Logger++ to capture all requests with timestamps

---

## 🔗 Related Notes
- [[Autorize-Plugin]]
- [[IDOR-Techniques]]
- [[JWT-Misconfiguration]]

---
*Tags: #burpsuite #tools #bac*

---

## InQL — GraphQL BOLA Testing (Critical Extension)

InQL is the essential Burp extension for GraphQL BAC testing. Install it first before any GraphQL target.

```
BApp Store → search "InQL" → Install

Features:
  ✅ Auto-generates all queries and mutations from introspection
  ✅ Sends each to Repeater with one click
  ✅ Detects and decodes GraphQL over GET (often less protected)
  ✅ Batch query builder for rate-limit bypass
  ✅ Works even on non-standard GraphQL endpoints
```

**Workflow with InQL:**
```
1. Open InQL tab → enter GraphQL endpoint URL
2. Click "Analyze" → fetches schema via introspection
3. Review generated queries/mutations tree
4. Right-click any query → "Send to Repeater"
5. In Repeater: swap user IDs in variables → BOLA test
6. Try mutations as low-priv user → BFLA test
7. Check field list for sensitive fields (passwordHash, apiKey, ssn)
```

---

## Bambda Filters — Live BAC Detection (Burp 2024+)

Bambda filters let you write Java lambda expressions to filter the Proxy history in real time. Essential for large-scope BAC hunts.

```
Proxy → HTTP History → add filter → Bambda

# Filter 1: Show only requests where response contains PII-looking keys
// Show responses that may contain cross-account data
requestResponse.response() != null &&
requestResponse.response().bodyToString().contains("email") &&
requestResponse.response().bodyToString().contains("userId") &&
requestResponse.response().statusCode() == 200

# Filter 2: Show only 403 responses (build your bypass list)
requestResponse.response() != null &&
requestResponse.response().statusCode() == 403

# Filter 3: Show requests with numeric path parameters (IDOR candidates)
requestResponse.request().path().matches(".*/[0-9]{3,}/.*") ||
requestResponse.request().path().matches(".*/[0-9]{3,}$")

# Filter 4: Show requests with ID-sounding parameters
requestResponse.request().hasParameters() &&
(requestResponse.request().path().contains("_id") ||
 requestResponse.request().path().contains("userId") ||
 requestResponse.request().path().contains("account"))
```

**Save Bambda filters** as named presets — switch between "IDOR candidates", "403 bypass targets", and "admin endpoints" with one click.

---

## Updated Extension List (v2)

```
BApp Store — install all of these:
  ✅ Autorize           — Automated auth testing (core)
  ✅ AuthMatrix         — Multi-role permission matrix
  ✅ InQL               — GraphQL BOLA/BFLA (critical for API targets)
  ✅ JWT Editor         — JWT manipulation and signing
  ✅ Param Miner        — Mass assignment discovery
  ✅ GAP                — JS endpoint extraction
  ✅ 403 Bypasser       — Path bypass automation
  ✅ Turbo Intruder     — High-speed IDOR fuzzing + race conditions
  ✅ Logger++           — Advanced logging with timestamps
  ✅ Burp Bambda        — (built into Burp 2024.1+, no install needed)
```
