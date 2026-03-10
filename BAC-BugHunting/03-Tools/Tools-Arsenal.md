---
tags: [bac, tools, arsenal, reference]
type: tools
date: 2026-03-10
---

# 🛠 Tools Arsenal — Which Tool for Which Job

> Quick-decision reference. Find the right tool fast without re-reading full docs.

---

## Decision Matrix

| Situation | Best Tool | Second Choice |
|---|---|---|
| Automated IDOR detection across full session | **Autorize** (Burp) | AuthMatrix |
| Fuzz 10,000 sequential IDs fast | **Turbo Intruder** | ffuf |
| Discover hidden admin paths | **feroxbuster** | ffuf + AdminPanels.txt |
| Find hidden POST parameters | **Param Miner** (Burp) | Arjun |
| Extract endpoints from JS files | **GAP** (Burp) | LinkFinder |
| Attack JWT tokens (all vectors) | **jwt_tool** | Burp JWT Editor |
| CORS misconfiguration bulk check | **curl bash script** | Burp active scan |
| Mass scan targets with BAC templates | **Nuclei** | Custom ffuf |
| Crack JWT HMAC secret | **hashcat** (`-m 16500`) | jwt_tool `-C` |
| Test WebSocket messages | **Burp WS Repeater** | wscat (CLI) |
| OAuth flow analysis & attacks | **Burp + OAuth Tester** | Manual Repeater |
| Discover API docs (Swagger etc.) | **ffuf + api-docs.txt** | kiterunner |
| Multi-role permission matrix test | **AuthMatrix** (Burp) | Manual Repeater |
| GraphQL introspection + IDOR | **InQL** (Burp) | clairvoyance |
| Subdomain enumeration (for CORS chain) | **subfinder + httpx** | amass |
| Git repo extraction (`.git` exposed) | **git-dumper** | GitTools |
| Real-time traffic diff between roles | **Burp Comparer** | diff tool |

---

## 📦 Installation — Everything in One Block

```bash
# ── Burp Suite Extensions (BApp Store — install in UI) ──────────────────
# Autorize, AuthMatrix, JWT Editor, Param Miner, GAP,
# Turbo Intruder, InQL, Logger++, 403 Bypasser, OAuth Tester

# ── Python tools ─────────────────────────────────────────────────────────
pip install arjun                         # Hidden param discovery
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip install -r requirements.txt
git clone https://github.com/GerbenJavado/LinkFinder && pip install -r requirements.txt
git clone https://github.com/hannob/snallygaster  # Secret file scanner
pip install corscanner                    # CORS bulk checker
git clone https://github.com/nicowillis/graphql-ferret  # GraphQL enum

# ── Go tools ─────────────────────────────────────────────────────────────
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/jaeles-project/kiterunner/cmd/kr@latest   # API route brute-force

# ── Rust tools ───────────────────────────────────────────────────────────
cargo install feroxbuster                 # Best recursive dir scanner

# ── Standalone ───────────────────────────────────────────────────────────
git clone https://github.com/arthaud/git-dumper && pip install git-dumper
git clone https://github.com/nicowillis/clairvoyance  # Blind GraphQL introspection

# ── Wordlists ─────────────────────────────────────────────────────────────
git clone https://github.com/danielmiessler/SecLists ~/wordlists/SecLists
# Key lists:
# ~/wordlists/SecLists/Discovery/Web-Content/common.txt
# ~/wordlists/SecLists/Discovery/Web-Content/AdminPanels.txt
# ~/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
# ~/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt
# ~/wordlists/SecLists/Fuzzing/jwt-secrets.txt
```

---

## 🚀 One-Liner Recipes by Goal

### Goal: Find admin panels in 30 seconds
```bash
feroxbuster -u https://TARGET.com \
  -w ~/wordlists/SecLists/Discovery/Web-Content/AdminPanels.txt \
  -mc 200,301,302,403 -x php,html,json -t 50 --silent
```

### Goal: IDOR fuzz a numeric ID endpoint
```bash
ffuf -u https://TARGET.com/api/orders/FUZZ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -w <(seq 1 10000) \
  -mc 200 -fs 50 -t 40 -o idor_hits.json -of json
```

### Goal: Discover hidden POST body parameters
```bash
arjun -u https://TARGET.com/api/profile \
  -m POST \
  --headers "Authorization: Bearer TOKEN" \
  --stable -q
```

### Goal: Bulk CORS check across all endpoints
```bash
cat endpoints.txt | while read url; do
  res=$(curl -sk -H "Origin: https://evil.com" \
    -H "Cookie: SESSION" -I "$url" 2>/dev/null \
    | grep -i "access-control")
  [[ -n "$res" ]] && echo "$url → $res"
done
```

### Goal: Extract all API endpoints from live JS files
```bash
# 1. Collect all JS URLs
echo "https://TARGET.com" | gau | grep "\.js$" > js_urls.txt
# 2. Extract endpoints from each
cat js_urls.txt | while read jsurl; do
  curl -sk "$jsurl" | grep -Eo '["'"'"'](/api/[^"'"'"']+)["'"'"']'
done | sort -u | tee api_endpoints.txt
```

### Goal: GraphQL full recon
```bash
# Introspection
curl -sk -X POST https://TARGET.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Clairvoyance (blind introspection)
python3 clairvoyance.py -u https://TARGET.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  -o schema.json
```

### Goal: Crack JWT secret
```bash
hashcat -a 0 -m 16500 \
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIG" \
  ~/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

### Goal: Test all path bypass variants on a single 403
```bash
TARGET="https://TARGET.com"; BLOCKED="/admin/users"; COOKIE="session=TOKEN"
for p in "ADMIN/users" "admin//users" "admin/./users" "%61dmin/users" \
          "admin;/users" "admin..;/users" "api/../admin/users" \
          "admin%2fusers" "public/../../admin/users"; do
  code=$(curl -sk -o/dev/null -w "%{http_code}" -H "Cookie: $COOKIE" "$TARGET/$p")
  [[ "$code" != "403" && "$code" != "404" && "$code" != "401" ]] \
    && echo "[!] $code → /$p"
done
```

### Goal: kiterunner — brute-force undocumented API routes
```bash
kr scan https://TARGET.com \
  -w ~/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt \
  -H "Authorization: Bearer TOKEN" \
  --fail-status-codes 400,401,403,404,429,500 -x 20
```

---

## 🔗 Related Notes
- [[Burp-Suite-BAC]] | [[Autorize-Plugin]] | [[Nuclei-BAC]] | [[Custom-Scripts]]
- [[Testing-Checklist]] | [[00-CHEATSHEET]]

---
*Tags: #tools #arsenal #reference #bac*
