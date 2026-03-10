---
tags: [bac, methodology, recon, reconnaissance]
type: methodology
date: 2026-03-10
---

# 🔭 Recon Phase — BAC Hunting

## Objective
Before testing BAC, understand the app's **identity model**, **role structure**, **object model**, and **API surface** completely. Good recon = finding more bugs faster.

---

## Step 1: Understand the Application

### Questions to Answer Before Testing
```
1. What roles exist? (guest, user, premium, moderator, admin, superadmin, staff, support)
2. What objects/resources does the app manage?
   → Users, orders, files, messages, invoices, reports, config, projects
3. What operations exist per resource?
   → CRUD: Create, Read, Update, Delete + custom actions
4. What identifies objects? (integer IDs, UUIDs, slugs, hashes)
5. Is there multi-tenancy? (organizations, workspaces, teams)
6. What authentication mechanisms? (session cookies, JWTs, API keys, OAuth)
7. What API style? (REST, GraphQL, SOAP, gRPC)
```

---

## Step 2: Account Setup
```
Create accounts:
  ✓ Role A: Guest / Unauthenticated
  ✓ Role B: Standard User (Account 1 - ATTACKER)
  ✓ Role C: Standard User (Account 2 - VICTIM)  ← different user, same role
  ✓ Role D: Premium / Paid User (if possible)
  ✓ Role E: Admin (if self-registration possible or if bug bounty provides)

For each account, note:
  - Session cookie or JWT
  - User ID / Account ID
  - Any resource IDs belonging to that account (order IDs, file IDs, etc.)
```

---

## Step 3: API Discovery

### From JavaScript Files
```bash
# Download all JS files from target
wget -r -l1 -A "*.js" https://target.com -P ./js_files/

# Extract all API endpoints
grep -rEo '["'"'"'](/[a-zA-Z0-9_/.-]+)["'"'"']' ./js_files/ | \
  grep -v ".css\|.png\|.jpg" | sort -u > endpoints.txt

# Look for admin indicators
grep -i "admin\|internal\|manage\|staff\|super" endpoints.txt

# Tools:
# LinkFinder: python3 linkfinder.py -i https://target.com -d
# JSParser: python3 jsparser.py https://target.com
# Burp → Target → Site map → right-click → "Engagement tools → Find scripts"
```

### From Swagger / OpenAPI
```bash
# Discover API docs
ffuf -u https://target.com/FUZZ -w ~/wordlists/api-docs.txt
# Wordlist includes: swagger.json, openapi.json, api-docs, 
#   v1/swagger, api/swagger.json, docs/api, etc.

# Parse OpenAPI for all endpoints + auth requirements
python3 -c "
import json, requests
api = requests.get('https://target.com/swagger.json').json()
for path, methods in api.get('paths', {}).items():
    for method, details in methods.items():
        auth = 'security' in details
        print(f'{method.upper()} {path} | auth={auth}')
"
```

### From Mobile Apps
```bash
# Android APK
apktool d target.apk -o decompiled/
grep -r "api\|endpoint\|https://" decompiled/ | grep -v ".png\|.jpg"

# Using jadx for better decompilation
jadx -d decompiled_jadx/ target.apk
grep -r "BuildConfig\|BASE_URL\|API_URL" decompiled_jadx/
```

### From GitHub Recon
```
Google dorks:
  site:github.com "target.com" "api/v"
  site:github.com "target.com" "Authorization"
  site:github.com "target.com" "admin" "endpoint"
  site:github.com/target "API_KEY"

GitHub search:
  "target.com" + "api" + language:javascript
  org:target-org "api/internal"
```

### From Web Archive
```bash
# Get all URLs from Wayback Machine
waybackurls target.com | grep "/api\|/admin\|/internal" | sort -u

# Or using gau
gau target.com | grep "api\|admin" | sort -u
```

---

## Step 4: Role & Permission Mapping

Create a permission matrix spreadsheet:

```
Endpoint              | Guest | User | Admin | Notes
/api/users/me         |  403  |  200 |  200  | 
/api/users/{id}       |  403  |  403 |  200  | ← Test IDOR here
/api/admin/users      |  403  |  403 |  200  | ← Test VertPrivEsc
/api/orders/{id}      |  403  |  ?   |  200  | ← Test IDOR here
/api/admin/config     |  403  |  403 |  200  | ← Test VertPrivEsc
```

---

## Step 5: Object ID Collection
```
Systematically collect object IDs belonging to Victim account:
  ✓ Order IDs (from order confirmation emails)
  ✓ File IDs (from upload responses)
  ✓ Message IDs (from message API responses)
  ✓ Invoice IDs (from billing section)
  ✓ Report IDs (from report generation)
  ✓ User ID (from profile API /api/me)
  ✓ API keys (from settings)
  ✓ Project IDs (from project creation)
  
→ These become your IDOR test targets
```

---

## Recon Tasks
- [ ] #task Create 2+ test accounts (attacker + victim)
- [ ] #task Download and parse all JS files for endpoints
- [ ] #task Check for Swagger/OpenAPI documentation
- [ ] #task Run waybackurls / gau for historical endpoints
- [ ] #task GitHub recon for target's codebase and API patterns
- [ ] #task Map all roles and their expected permissions
- [ ] #task Collect all Victim's object IDs for IDOR testing
- [ ] #task Check mobile app (if exists) for additional endpoints
- [ ] #task Search for Postman collections (Postman public workspace search)

---

## 🔗 Related Notes
- [[Testing-Checklist]]
- [[BAC-Overview]]
- [[Burp-Suite-BAC]]

---
*Tags: #recon #methodology #bac*

---

## Step 6: Cloud Asset Recon

```bash
# ── S3 Bucket Discovery ────────────────────────────────────────────────
# Naming patterns: {company}, {company}-dev, {company}-prod,
#                  {company}-backup, {company}-uploads, {company}-assets
TARGET="companyname"
for suffix in "" "-dev" "-prod" "-staging" "-backup" "-uploads" \
              "-assets" "-exports" "-data" "-logs" "-internal"; do
    bucket="${TARGET}${suffix}"
    if aws s3 ls "s3://${bucket}" --no-sign-request 2>/dev/null; then
        echo "[FOUND] s3://${bucket} - PUBLICLY ACCESSIBLE!"
    fi
done

# ── Lambda Function URL Discovery ─────────────────────────────────────
# Search JS files and APKs:
grep -r "lambda-url\|\.lambda-url\.\|on\.aws" ./js_files/ 2>/dev/null

# Google dork:
# site:*.lambda-url.us-east-1.on.aws
# site:*.lambda-url.eu-west-1.on.aws

# ── Cognito Pool Discovery ─────────────────────────────────────────────
grep -r "cognito\|IdentityPoolId\|UserPoolId" ./js_files/ 2>/dev/null
# Format: us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# ── API Gateway Discovery ──────────────────────────────────────────────
# Format: https://API_ID.execute-api.REGION.amazonaws.com/STAGE/
grep -rEo "[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com" ./js_files/ 2>/dev/null

# ── GCP Cloud Function Discovery ──────────────────────────────────────
grep -r "cloudfunctions\.net\|run\.app\|appspot\.com" ./js_files/ 2>/dev/null
```

---

## Step 7: Shodan & Censys Recon for Admin Interfaces

```
Shodan searches for exposed admin/internal services:

For a specific organization:
  org:"Target Corp" http.title:"Admin"
  org:"Target Corp" http.status:200 http.title:"Dashboard"
  org:"Target Corp" http.status:200 "api" port:8080,8443,3000,4000,5000

Kubernetes dashboards (often no auth):
  http.title:"Kubernetes Dashboard"
  http.title:"Kubernetes" http.status:200

Jenkins (often accessible):
  http.title:"Dashboard [Jenkins]" http.status:200

Grafana (default creds / no auth):
  http.title:"Grafana" http.status:200

Swagger UI (exposed API docs):
  http.title:"Swagger UI" org:"Target Corp"
  http.html:"swagger" org:"Target Corp"

GraphQL Playground exposed:
  http.html:"graphql-playground" org:"Target Corp"
  http.title:"GraphQL Playground"

Exposed .env / config files (Shodan + Google):
  http.html:"DB_PASSWORD" "APP_KEY" org:"Target Corp"

Google dorks for BAC:
  site:target.com filetype:env
  site:target.com inurl:swagger
  site:target.com inurl:graphql
  site:target.com inurl:admin "login"
  site:target.com intitle:"Index of" "backup"
  site:target.com inurl:".git" OR inurl:".env"
```

---

## Step 8: gRPC Service Discovery

```bash
# Scan for gRPC ports (common: 50051, 443, 8080, 9090, 9000)
nmap -sV -p 50051,443,8080,9090,9000 target.com

# Test gRPC reflection (service enumeration):
grpcurl -plaintext target.com:50051 list 2>&1
grpcurl -plaintext target.com:9090 list 2>&1
# Also test on 443 (TLS):
grpcurl target.com:443 list 2>&1

# If reflection works, enumerate all services and methods:
grpcurl -plaintext target.com:50051 list | while read svc; do
    echo "=== $svc ==="
    grpcurl -plaintext target.com:50051 list "$svc"
    grpcurl -plaintext target.com:50051 describe "$svc"
done > grpc_full_schema.txt

# Search GitHub for .proto files:
# site:github.com org:TARGET "*.proto"
# site:github.com "target.com" language:protobuf
```

---

## Updated Recon Tasks

- [ ] #task S3 buckets enumerated with naming pattern variations
- [ ] #task Lambda Function URLs searched in JS/mobile code
- [ ] #task Cognito identity pool IDs found and tested for unauth access
- [ ] #task API Gateway endpoint URLs discovered from JS/mobile
- [ ] #task Shodan searched for exposed admin panels, Swagger, GraphQL
- [ ] #task Google dorks run for .env, .git, swagger, admin exposure
- [ ] #task gRPC ports scanned (50051, 443, 8080, 9090)
- [ ] #task gRPC reflection tested — services/methods enumerated if open
