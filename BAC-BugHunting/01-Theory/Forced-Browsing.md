---
tags: [bac, theory, forced-browsing, unprotected-endpoints]
type: theory
severity: high
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🚪 Forced Browsing — Direct Access to Unprotected Resources

## Definition
Forced browsing occurs when an application **does not enforce access control on URLs**, relying instead on obscurity — the assumption that users won't guess or find the path. This is "security through obscurity" and it always fails.

---

## Attack Surface Map

```
Forced Browsing Targets:
├── Admin Interfaces
│   ├── /admin, /administrator, /administration
│   ├── /manage, /management, /manager
│   ├── /staff, /moderator, /superuser, /su
│   ├── /control-panel, /cpanel, /panel
│   ├── /dashboard, /console, /backend
│   └── /ops, /internal, /system
│
├── Sensitive Functionality Pages
│   ├── /setup, /install, /installer
│   ├── /config, /configuration, /settings
│   ├── /debug, /test, /dev, /development
│   ├── /phpinfo.php, /info.php
│   └── /server-status, /server-info (Apache)
│
├── Backup & Source Files
│   ├── /backup/, /backups/, /bkp/
│   ├── index.php.bak, config.php~, .config.swp
│   ├── /source/, /src/, /code/
│   ├── /.git/config, /.git/HEAD, /.svn/entries
│   └── /dump.sql, /database.sql, /backup.zip
│
├── API Documentation (often publicly accessible)
│   ├── /swagger.json, /swagger.yaml
│   ├── /openapi.json, /api-docs
│   ├── /graphiql, /graphql-playground
│   └── /api/v1, /api/v2, /api/internal
│
├── Log & Debug Files
│   ├── /logs/, /log/, /error.log, /access.log
│   ├── /debug.log, /application.log
│   └── /.env, /.env.production, /.env.local
│
└── User-Specific Resources (no auth required)
    ├── /users/1337/export (direct URL)
    ├── /reports/Q4-2024-financial.pdf
    └── /uploads/user_contracts/agreement_12345.pdf
```

---

## Testing Methodology

### Step 1: Wordlist-Based Discovery
```bash
# ffuf with SecLists admin wordlist
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,403 \
  -fc 404 \
  -o forced-browsing.json

# Specifically for admin panels
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/AdminPanels.txt \
  -mc 200,301,302 -t 50

# DirSearch (recursive)
python3 dirsearch.py -u https://target.com \
  -e php,html,js,json,txt,bak,config \
  --deep-recursive

# Feroxbuster (fastest, Rust-based)
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,html,js,json,txt,bak \
  -r --depth 3
```

### Step 2: Test Discovered Paths With Low-Priv Session
```bash
# After discovery, test each path as authenticated user
# and as unauthenticated (no cookie)

for path in $(cat discovered_paths.txt); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Cookie: session=LOW_PRIV_TOKEN" \
    "https://target.com$path")
  echo "$code $path"
done | grep "^200\|^201\|^301"
```

### Step 3: Sensitive File Discovery
```bash
# Check for backup / source file exposure
for ext in bak backup~ .swp .old .orig .copy; do
  ffuf -u https://target.com/FUZZ$ext \
    -w common-filenames.txt -mc 200
done

# Git exposure
git-dumper https://target.com/.git/ ./dumped-repo/

# .env exposure (critical)
curl -s https://target.com/.env | head -20
```

### Step 4: Authenticated Page Direct Access
```
Test: Can a low-priv user directly access high-priv pages?

Examples:
  Regular user tries: https://target.com/admin/dashboard
  Regular user tries: https://target.com/admin/users/list
  Regular user tries: https://target.com/internal/reports/financial

If server renders the page (not just 200 with error msg inside),
it's a confirmed forced browsing vulnerability.
```

---

## Special Cases

### Setup/Install Page Exposure
```
Risk: Critical — often allows creating admin accounts post-install
Check: /setup, /install, /installer, /wizard, /setup.php
Famous example: CVE-2023-22515 (Confluence)
```

### API Version Exposure
```
/api/v1/admin  → patched
/api/v0/admin  → still works!
/api/beta/admin → beta version, less hardened
/api/internal/admin → internal, no auth enforced
```

### Predictable Export URLs
```
/exports/users-2024-01-15.csv
/reports/financial-Q4-2024.xlsx
/backups/2024-12-31-database.sql
→ Guess filename patterns from known URLs
```

---

## Tools Summary
```
ffuf         → General fuzzing, fastest
feroxbuster  → Recursive, multi-threaded, Rust
dirsearch    → Recursive, many extensions
gobuster     → Simple dir/file brute force
git-dumper   → Extract exposed .git repos
```

---

## Tasks
- [ ] #task Run feroxbuster on target's root with large wordlist
- [ ] #task Check for /.git/, /.env, /backup/, /swagger.json exposure
- [ ] #task Test discovered paths with low-priv and unauthenticated session
- [ ] #task Check for old API versions (/api/v0, /api/beta, /api/internal)
- [ ] #task Look for predictable file exports and download URLs
- [ ] #task Check for /setup, /install endpoints

---

## 🔗 Related Notes
- [[BAC-Overview]]
- [[Privilege-Escalation]]
- [[Bypass-Payloads]]
- [[Recon-Phase]]

---
*Tags: #forced-browsing #bac #theory #recon*
