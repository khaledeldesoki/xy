---
tags: [bac, idor, theory, high-severity]
type: theory
severity: high
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🎯 IDOR — Insecure Direct Object Reference

## Definition
IDOR occurs when an application uses **user-controllable input to access objects directly** without proper authorization checks. The server trusts that if you know the ID, you're allowed to access it.

---

## How It Works

```
Normal Flow:
  User A → GET /api/invoice/1001 → ✅ Returns User A's invoice

IDOR Attack:
  User A → GET /api/invoice/1002 → ✅ Returns User B's invoice (BUG!)
```

The application: (1) takes the ID from user input, (2) queries the database directly, (3) returns result **without checking ownership**.

---

## IDOR Types — All 10

### 1. Numeric Sequential IDOR
```http
GET /api/users/1337/profile → Try: /api/users/1338/profile, /api/users/1/profile
```

### 2. GUID/UUID IDOR
```http
GET /api/docs/3f6a92b1-4c8d-4e2a-9d71-abc123def456
→ Leak GUIDs via: email links, logs, other API responses, Referer headers
```

### 3. Hash-Based IDOR
```http
GET /download?file=5f4dcc3b5aa765d61d8327deb882cf99  (MD5 of filename)
→ Compute MD5 of target filename
```

### 4. Encoded IDOR
```http
GET /api/record/dXNlcl8xMzM3  (base64: "user_1337")
→ Decode → modify → re-encode
```

### 5. Blind IDOR (no response but action happens)
```http
DELETE /api/notifications/9876
→ No content returned, but victim's item is deleted
→ Verify by checking victim account afterward
```

### 6. HTTP Parameter Pollution IDOR
```http
GET /api/profile?user_id=me&user_id=1337
→ Server may process the second parameter
```

### 7. IDOR in JSON Body
```json
POST /api/update-profile
{"user_id": 1337, "email": "hacker@evil.com"}
```

### 8. IDOR via Path Parameter
```http
GET /users/1337/settings → change 1337
PUT /orders/9999/cancel  → change 9999
```

### 9. Indirect Reference IDOR (Chained)
```http
Step 1: GET /api/me → {"account_id": "ACC-5001"}
Step 2: GET /api/account/ACC-5001/statement → try ACC-5002
```

### 10. File Download IDOR
```http
GET /files/download?id=invoice_1337.pdf
GET /export?report_id=2024-Q4-usr1337
```

---

## Where to Hunt IDOR

```
HIGH-VALUE ENDPOINTS:
  /api/user/{id}              /api/account/{id}
  /api/order/{id}             /api/payment/{id}
  /api/message/{id}           /api/document/{id}
  /api/admin/user/{id}        /api/ticket/{id}
  /api/invoice/{id}           /api/report/{id}/download

ID LOCATIONS — check ALL of these:
  → URL path parameters
  → Query string (?user_id=, ?account=, ?doc=)
  → JSON request body
  → Cookie values
  → HTTP headers (X-User-Id, X-Account, etc.)
  → Hidden form fields
  → Referrer URLs from emails/notifications
  → WebSocket messages
```

---

## Hunting Methodology

### Phase 1: Account Setup
- [ ] #task Create **Account A** (attacker) and **Account B** (victim) — both same role
- [ ] #task Create resources with Account B: orders, files, messages, reports
- [ ] #task Collect all object IDs belonging to Account B

### Phase 2: Map Reference Points
- [ ] #task Use Burp sitemap to collect all requests with ID parameters
- [ ] #task Parse JS files for hidden API endpoints: `grep -r '"api/' *.js`
- [ ] #task Check mobile app traffic if applicable

### Phase 3: Test with Account A
- [ ] #task Swap Account B's IDs into every request using Account A's token
- [ ] #task Run Autorize plugin across the full authenticated session
- [ ] #task Test all HTTP methods: GET, POST, PUT, DELETE, PATCH
- [ ] #task Test with no auth token (unauthenticated access)

### Phase 4: Blind IDOR Verification
```
When you DELETE/PUT/PATCH via IDOR and get an empty 200/204:
  1. Log into victim account → check if the resource changed/disappeared
  2. Check if victim receives an email triggered by the action
  3. Re-request the resource as victim → if 404 it was deleted
  4. Screenshot the victim account state BEFORE the attack as baseline
  This proves the IDOR actually worked on victim's data — essential for reports
```

---

## Impact Examples

| Endpoint | Impact |
|---|---|
| `/api/user/{id}/export` | Dump any user's full PII |
| `/api/payment/{id}` | Access payment methods and card data |
| `/api/user/{id}/reset-token` | Steal password reset token → ATO |
| `/api/admin/user/{id}/delete` | Delete any user account |
| `/api/order/{id}/refund` | Refund others' orders to your account |
| `/api/document/{id}` | Access confidential contracts |

---

## 🔗 Related Notes
- [[Horizontal-vs-Vertical]] — conceptual framework
- [[IDOR-Techniques]] — exploitation methods in depth
- [[IDOR-Payloads]] — wordlists, ID patterns, ffuf commands
- [[Autorize-Plugin]] — automated IDOR detection setup
- [[Burp-Suite-BAC]] — Intruder / Turbo Intruder IDOR fuzzing
- [[Testing-Checklist]] — full testing checklist with all IDOR tasks
- [[WebSocket-BAC]] — IDOR via WebSocket messages
- [[Advanced-BAC-Chains]] — chaining IDOR into ATO and beyond
- [[Findings-Database]] — log confirmed bugs here

---
*Tags: #idor #bac #theory*
