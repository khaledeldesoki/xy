---
tags: [bac, methodology, flowchart, decision, reference]
type: methodology
date: 2026-03-10
---

# 🗺 Decision Flowchart — What to Test When

> Mid-hunt navigation tool. You see something → follow the tree → know exactly what to test next. No re-reading full guides.

---

## Flowchart 1: I Found an Endpoint That Accepts an ID

```
Endpoint accepts an ID (path, query, body, header)
│
├── Is the ID an integer?
│   ├── YES → Fuzz ±1, ±100, 1, 0, -1 with your token → IDOR?
│   └── NO  → Is it base64? Decode → modify → re-encode → test
│              Is it UUID? Source it from another endpoint → swap → test
│              Is it a hash? Identify algo → compute for target value → test
│
├── Does the endpoint allow READ?
│   ├── Test with YOUR token on VICTIM's ID → returns victim data? → IDOR (read)
│   └── Test with NO token → returns data? → Unauthenticated IDOR (critical)
│
├── Does the endpoint allow WRITE (PUT/PATCH/POST/DELETE)?
│   ├── Test DELETE with victim's ID → check if victim's resource disappears → Blind IDOR
│   └── Test PUT/PATCH with victim's ID → can you modify victim's data? → IDOR (write)
│
└── Can you CHAIN it?
    ├── Does the response contain a reset_token, api_key, or secret? → ATO chain
    ├── Is there a CORS misconfig on this endpoint? → Remote authenticated exfil
    └── Does it expose an email you can use for phishing/reset? → Log and note
```

---

## Flowchart 2: I Got a 403 on an Admin Endpoint

```
GET /admin/users → 403
│
├── Try path normalization variants first (fastest, no auth needed):
│   /ADMIN/users  /admin//users  /admin/./users
│   /%61dmin/users  /admin;/users  /admin..;/users
│   → Any non-403? → Confirmed bypass
│
├── Try header-based bypass (add to original request):
│   X-Forwarded-For: 127.0.0.1
│   X-Original-URL: /admin/users  (with GET /)
│   X-Custom-IP-Authorization: 127.0.0.1
│   → Any 200? → Confirmed bypass
│
├── Try HTTP method swap:
│   POST, PUT, DELETE, HEAD, OPTIONS on same path
│   → HEAD returns 200? → Endpoint accessible
│   → OPTIONS reveals allowed methods? → Try each
│
├── Are you authenticated?
│   ├── NO  → Also try with low-priv session token
│   └── YES → Try with different role account (do you have admin test account?)
│
└── Is this a Spring Boot app?
    → /admin..;/users  and  /actuator/..;/admin  are high-probability bypasses
```

---

## Flowchart 3: I Found a JWT

```
JWT found (Authorization header / cookie / storage)
│
├── Decode the header → what algorithm?
│   │
│   ├── "alg": "none" already? → Weird. Test anyway.
│   │
│   ├── "alg": "HS256" (HMAC)
│   │   ├── Try alg:none → python3 jwt_tool.py TOKEN -X a
│   │   ├── Try crack secret → hashcat -m 16500 TOKEN rockyou.txt
│   │   └── If cracked → re-sign with admin role → test
│   │
│   └── "alg": "RS256" (RSA)
│       ├── Try alg:none → python3 jwt_tool.py TOKEN -X a
│       ├── Try RS256→HS256 → fetch public key → jwt_tool TOKEN -X s -pk pubkey.pem
│       └── Look for jwks.json / x5c field in header
│
├── Decode the payload → what claims exist?
│   ├── "role" / "is_admin" / "scope" / "permissions"?
│   │   → Modify to admin values → re-sign if you have the secret
│   ├── "kid" header present?
│   │   → Test path traversal: "../../dev/null"
│   │   → Test SQLi: "x' UNION SELECT 'secret'-- "
│   └── "jwk" header present?
│       → Test JWK injection: jwt_tool TOKEN -X k
│
└── Is expiry enforced?
    → Set exp to past timestamp → test if server rejects it
```

---

## Flowchart 4: I Found an OAuth Flow

```
OAuth flow detected (redirect to /oauth/authorize?)
│
├── Capture the full authorization URL
│   ?client_id=X&redirect_uri=Y&state=Z&scope=W
│
├── Test redirect_uri manipulation:
│   → Replace with https://evil.com → does server allow it?
│   → Try subdomain: https://target.com.evil.com
│   → Try path traversal: https://target.com/callback/../../../evil
│   → Try @ encoding: https://target.com@evil.com
│
├── Is state parameter present?
│   ├── NO → OAuth CSRF possible → no state = missing CSRF protection
│   └── YES → Is it validated? Remove it → does flow still complete?
│
├── After getting auth code:
│   ├── Can you reuse the same code twice? → Code replay attack
│   └── Check URL bar / Referer of next page → is code leaking to 3rd parties?
│
├── Test scope escalation in token exchange:
│   Add "admin:all" to scope parameter → does server grant it?
│
└── Decode the access token — is it a JWT?
    → Yes → Apply JWT flowchart above
```

---

## Flowchart 5: I Found a GraphQL Endpoint

```
GraphQL endpoint confirmed (/graphql, /api/graphql, etc.)
│
├── Run introspection first:
│   → curl -X POST /graphql -d '{"query":"{ __schema { types { name } } }"}'
│   ├── Returns schema? → Run InQL in Burp for full analysis
│   └── Blocked? → Try field suggestion trick: { user(id:"1") { emal } }
│                   → "Did you mean email?" → reveals field names
│
├── Map schema for BAC targets:
│   → Object queries (user, order, invoice) → test BOLA (swap IDs)
│   → Mutations (delete, update, create) → test BFLA (call as low-priv)
│   → Sensitive fields (passwordHash, apiKey, ssn) → test field-level auth
│
├── Test BOLA on every object query:
│   → swap integer IDs, UUID/string IDs
│   → test unauthenticated access
│
├── Test BFLA on mutations:
│   → Call deleteUser, updateRole, createAdmin as regular user
│
├── Rate limits present?
│   → Batch 100 queries into single HTTP request → bypass rate limit
│
└── Does the app use WebSocket for GraphQL?
    → Test subscription with victim's user ID
    → See [[WebSocket-BAC]] for token auth patterns
```

---

## Flowchart 6: I Found a WebSocket Connection

```
WebSocket traffic detected (DevTools → Network → WS)
│
├── Log ALL messages during normal session (Burp WS History)
│
├── Do messages contain resource IDs?
│   ├── YES → Swap IDs → IDOR via WebSocket
│   └── NO  → Look for action/type fields → test admin actions
│
├── How does WS authenticate?
│   ├── Cookie in handshake → test with low-priv cookie
│   └── ?token= in URL → test with modified JWT (alg:none, role: admin)
│
├── Can you subscribe to another user's channel?
│   {"action": "subscribe", "user_id": "VICTIM_ID", "channel": "updates"}
│
└── Try admin actions via WS:
    {"action": "admin.listUsers"}
    {"action": "user.setRole", "user_id": "MY_ID", "role": "admin"}
    → Often less protected than HTTP admin API
```

---

## Flowchart 7: I'm On a Cloud-Hosted Target

```
Target uses AWS / GCP / Azure (check response headers, JS files, DNS)
│
├── Is there an S3 bucket?
│   → aws s3 ls s3://COMPANY-NAME --no-sign-request
│   → Try variants: -backup, -prod, -uploads, -exports, -assets
│
├── Any Lambda Function URLs in JS/mobile?
│   → Format: FUNCTION_ID.lambda-url.REGION.on.aws
│   → Test unauthenticated: curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/
│   → Test admin paths: /admin, /api/admin, /internal
│
├── Any Cognito IDs in JS? (format: us-east-1:GUID)
│   → Test unauthenticated identity pool access
│
├── API Gateway URLs? (FORMAT_ID.execute-api.REGION.amazonaws.com)
│   → Test without auth credentials
│   → Test with expired/wrong credentials
│
└── SSRF found on target?
    → AWS IMDS:  http://169.254.169.254/latest/meta-data/iam/security-credentials/
    → GCP IMDS:  http://metadata.google.internal/computeMetadata/v1/ (+ Metadata-Flavor: Google)
    → Azure IMDS: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

---

## Flowchart 8: I Got a Finding — What Severity?

```
Found a BAC bug — what CVSS?
│
├── Is authentication required to exploit?
│   ├── NO (unauthenticated) → PR:N → at least 9.1 Critical
│   └── YES (authenticated)  → PR:L → continue
│
├── What data is exposed / what action is possible?
│   ├── PII (email, phone, address, DOB, SSN) → C:H
│   ├── Financial (payment methods, transactions, bank) → C:H → consider 8.1+
│   ├── Credentials / tokens / API keys → C:H → check if chain to ATO
│   ├── Non-sensitive metadata only → C:L → Medium range
│   └── Write/delete on victim data → I:H → add to CVSS
│
├── Can you chain it?
│   ├── + Password reset token → ATO → 9.8 Critical
│   ├── + Admin access → 9.8 Critical
│   ├── + CORS misconfig → Remote exploit → raise by 0.5–1.0
│   └── No chain → score as-is
│
└── Regulation applicable?
    ├── EU users → mention GDPR Article 83 in impact
    ├── US healthcare → mention HIPAA civil penalties
    ├── Payment data → mention PCI-DSS Requirement 7
    └── California users → mention CCPA §1798.150
    → These escalate program's perceived severity and payout
```

---

## 🔗 Jump To
[[Testing-Checklist]] · [[00-CHEATSHEET]] · [[Why-Reports-Fail]] · [[Reporting-BAC]]
[[IDOR-Techniques]] · [[Privilege-Escalation]] · [[GraphQL-BAC]] · [[Race-Condition-BAC]]

---
*Tags: #methodology #flowchart #decision #bac*
