---
tags: [bac, tools, autorize, burp]
type: tools
date: 2026-03-10
---

# 🔌 Autorize — Automated Authorization Testing

## What Autorize Does
Autorize intercepts every request in Burp and **automatically replays it** with a different (lower-privilege) session. It then compares responses to determine if access control is enforced.

## Installation
```
Burp Suite → Extender → BApp Store → Search "Autorize" → Install
```

## Full Configuration Guide

### Setup Low-Privilege Cookie
```
1. Login as VICTIM user (the role you want to impersonate)
2. Copy the full Cookie header or Authorization header
3. In Autorize tab → paste into "Cookie / Authorization Header value"
   Example: session=abc123; csrf=xyz789
   Or: Authorization: Bearer eyJhbGci...
```

### Configuration Options
```
Autorize tab settings:
  ✅ Intercept requests from Proxy
  ✅ Intercept requests from Repeater
  Check unauth? → Enable + clear cookie (test unauthenticated too)
  
Filters (optional, to reduce noise):
  Filter by extension: exclude .js .css .png .jpg .ico .woff
  Filter by status: only show 200 responses
  Filter by body: only show responses with "user" or "email" keywords
```

### Running Autorize
```
1. Enable Autorize (toggle button → green)
2. Browse the application as ATTACKER user
3. Perform ALL actions: view profile, orders, messages, invoices, etc.
4. Autorize replays each request with VICTIM cookie simultaneously
5. Watch the table fill with results

Color meaning:
  🔴 Bypassed!  = Attacker gets same response as victim (IDOR found!)
  🟡 Is enforced? = Similar response length, check manually
  🟢 Enforced!  = Server returned different/blocked response
```

### Reading Results
```
For each red item:
  1. Click the row
  2. View "Original" tab = victim's response (200 + data)
  3. View "Modified" tab = attacker's response (should be 403)
  4. If both 200 + similar body → CONFIRMED IDOR

Export:
  Right-click → "Export table to HTML/CSV"
  → Creates full evidence report
```

## Advanced: Testing Multiple Roles
```
For multi-role testing, run Autorize multiple times:
  Run 1: Victim cookie = Admin → Attacker = Regular User
  Run 2: Victim cookie = Regular User → Attacker = Guest
  Run 3: Victim cookie = Any User → Attacker = no cookie (unauth)
```

## Autorize + AuthMatrix Combo
```
AuthMatrix is better for systematic multi-role testing:
  1. Define all roles + their tokens
  2. Define all requests to test
  3. Mark expected access for each role
  4. Run → highlights permission matrix violations
```

---

## Tasks
- [ ] #task Install Autorize from BApp Store
- [ ] #task Configure with victim's session token
- [ ] #task Run through complete authenticated flow of target
- [ ] #task Export and review all red/yellow findings
- [ ] #task Re-run with empty cookie for unauthenticated testing

---

## 🔗 Related Notes
- [[Burp-Suite-BAC]]
- [[IDOR-Techniques]]
- [[Testing-Checklist]]

---
*Tags: #autorize #tools #burp #bac*
