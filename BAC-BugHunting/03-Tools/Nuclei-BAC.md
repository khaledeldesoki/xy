---
tags: [bac, tools, nuclei, automation]
type: tools
date: 2026-03-10
---

# ⚡ Nuclei — BAC Templates & Automation

## Installation & Setup
```bash
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# BAC-related template paths:
~/.local/nuclei-templates/http/exposures/
~/.local/nuclei-templates/http/misconfiguration/
~/.local/nuclei-templates/http/vulnerabilities/
~/.local/nuclei-templates/http/default-logins/
```

---

## Built-in BAC Templates
```bash
# Run all access control related templates
nuclei -u https://target.com -t http/exposures/ -t http/misconfiguration/
nuclei -u https://target.com -tags "access-control,idor,auth-bypass"

# Admin panel exposure
nuclei -u https://target.com -t http/exposures/panels/

# Sensitive endpoint exposure
nuclei -u https://target.com -t http/exposures/configs/

# Default credentials (often leads to BAC)
nuclei -u https://target.com -t http/default-logins/
```

---

## Custom IDOR Template
```yaml
# Save as: idor-basic.yaml
id: idor-numeric-id

info:
  name: Basic Numeric IDOR Test
  author: bughunter
  severity: high
  tags: idor, bac, authorization

variables:
  victim_id: "{{rand_int(1000, 9999)}}"

http:
  - raw:
      - |
        GET /api/user/{{victim_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}
        
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "email"
          - "phone"
          - "address"
        condition: or
    
    extractors:
      - type: regex
        name: user_data
        regex:
          - '"email":"([^"]+)"'
```

## Custom Admin Access Template
```yaml
id: admin-endpoint-bypass

info:
  name: Admin Endpoint Access as Low-Priv User
  author: bughunter
  severity: critical
  tags: privilege-escalation, bac

http:
  - raw:
      - |
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{low_priv_cookie}}
        
    attack: batteringram
    payloads:
      path:
        - admin
        - admin/users
        - admin/config
        - management
        - api/admin
        - api/v1/admin/users
        - internal/admin
        - superadmin
        
    matchers:
      - type: status
        status: [200]
        negative: false
      - type: word
        words: ["Unauthorized", "Forbidden", "403"]
        negative: true
```

## CORS Misconfiguration Template
```yaml
id: cors-reflected-origin

info:
  name: CORS Reflected Origin with Credentials
  severity: high
  tags: cors, bac, misconfig

http:
  - raw:
      - |
        GET /api/user/me HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.com
        Cookie: {{session_cookie}}
        
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
```

## JWT None Algorithm Template
```yaml
id: jwt-none-algorithm

info:
  name: JWT None Algorithm Attack
  severity: critical
  tags: jwt, bac, auth-bypass

http:
  - raw:
      - |
        GET /api/admin/users HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{jwt_none_token}}
        
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Unauthorized"]
        negative: true
```

---

## Running BAC Scan Pipeline
```bash
#!/bin/bash
TARGET=$1
COOKIE=$2
OUTPUT="nuclei-bac-$(date +%Y%m%d)"

echo "[*] Running BAC templates against $TARGET"

# Panel exposure
nuclei -u $TARGET -t http/exposures/panels/ \
  -H "Cookie: $COOKIE" -o "$OUTPUT-panels.txt"

# Misconfigurations (CORS, etc.)
nuclei -u $TARGET -t http/misconfiguration/ \
  -H "Cookie: $COOKIE" -o "$OUTPUT-misconfig.txt"

# Custom BAC templates
nuclei -u $TARGET -t ~/custom-templates/bac/ \
  -H "Cookie: $COOKIE" -o "$OUTPUT-custom.txt" -v

echo "[*] Done. Results in $OUTPUT-*.txt"
```

---

## Tasks
- [ ] #task Update nuclei templates to latest
- [ ] #task Run panel exposure templates on target
- [ ] #task Create custom IDOR template for target's ID format
- [ ] #task Run CORS misconfiguration template with session cookie
- [ ] #task Create admin endpoint bypass template for target paths

---

## 🔗 Related Notes
- [[Burp-Suite-BAC]]
- [[Custom-Scripts]]
- [[Testing-Checklist]]

---
*Tags: #nuclei #automation #bac #tools*

---

## ⚠️ Template Variable Fix — How to Pass Auth Credentials

The custom templates above use `{{token}}` and `{{low_priv_cookie}}` but these are not built-in Nuclei variables. Two ways to make them work:

### Option A — Declare in the template `variables:` block (static)
```yaml
id: idor-numeric-id

info:
  name: Basic Numeric IDOR Test
  severity: high
  tags: idor,bac

variables:
  token: "Bearer eyJhbGciOiJIUzI1NiJ9.YOUR_JWT_HERE"
  victim_id: "{{rand_int(1000, 9999)}}"

http:
  - raw:
      - |
        GET /api/user/{{victim_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: {{token}}
    matchers:
      - type: status
        status: [200]
```

### Option B — Pass at runtime via `-var` flag (flexible, recommended)
```bash
# Pass credentials at scan time — no hardcoded secrets in templates
nuclei -u https://target.com \
  -t ~/custom-templates/bac/idor-basic.yaml \
  -var token="Bearer YOUR_JWT" \
  -var low_priv_cookie="session=YOUR_COOKIE" \
  -v

# Combined with other templates:
nuclei -u https://target.com \
  -t ~/custom-templates/bac/ \
  -var token="Bearer TOKEN" \
  -var cookie="session=COOKIE" \
  -H "Authorization: Bearer TOKEN" \
  -o results.txt
```

### Complete corrected Admin Bypass template:
```yaml
id: admin-endpoint-bypass-v2

info:
  name: Admin Endpoint Access as Low-Priv User
  severity: critical
  tags: privilege-escalation,bac

variables:
  low_priv_cookie: "session=REPLACE_ME"   # or use -var at runtime

http:
  - raw:
      - |
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{low_priv_cookie}}

    attack: batteringram
    payloads:
      path:
        - admin
        - admin/users
        - admin/config
        - management
        - api/admin
        - api/v1/admin/users
        - internal/admin

    matchers-condition: and
    matchers:
      - type: status
        status: [200, 201, 204]
      - type: word
        words: ["Unauthorized", "Forbidden", "403", "Access Denied"]
        negative: true
```
