---
tags: [bac, theory, oauth, sso, authorization-code]
type: theory
severity: critical
owasp_ref: "A01:2021"
date: 2026-03-10
---

# 🔑 OAuth 2.0 & SSO — Access Control Vulnerabilities

## Why OAuth Creates BAC Vulnerabilities
OAuth 2.0 is an **authorization delegation framework**, not an authentication protocol. When apps misimplement it, the delegation model creates unique BAC flaws: state forgery, token leakage, scope escalation, and account takeover via authorization code theft.

---

## OAuth Flow — What Can Go Wrong

```
Standard Authorization Code Flow:
  1. App redirects user → Auth Server (?client_id=X&redirect_uri=Y&state=Z)
  2. User logs in + consents
  3. Auth Server → redirects to redirect_uri with ?code=ABC
  4. App exchanges code → POST /token (code=ABC) → access_token
  5. App uses access_token to call resource server

Attack surfaces:
  Step 1: redirect_uri manipulation
  Step 1: state parameter (CSRF)
  Step 2: Token leakage via Referer
  Step 3: Authorization code interception
  Step 4: Token scope escalation
  Step 5: Token reuse / insufficient validation
```

---

## Attack 1: redirect_uri Manipulation

```http
# Legitimate request:
GET /oauth/authorize?
  client_id=app123&
  redirect_uri=https://app.com/callback&
  response_type=code&
  scope=read

# Test manipulations:
redirect_uri=https://evil.com                          ← full replace
redirect_uri=https://app.com.evil.com                  ← subdomain spoof
redirect_uri=https://app.com/callback/../../../evil    ← path traversal
redirect_uri=https://app.com%40evil.com                ← @ encoding
redirect_uri=https://app.com/callback?redirect=https://evil.com  ← open redirect chain
redirect_uri=https://attacker.com%23app.com/callback   ← fragment bypass
redirect_uri=https://app.com%3A.evil.com               ← port confusion
```

**Impact**: Code received by attacker → exchange for access_token → access victim's account

---

## Attack 2: State Parameter CSRF

```
State param purpose: Binds authorization request to user's session
Missing state = CSRF on OAuth flow

Attack:
  1. Start OAuth flow, capture authorization URL with YOUR state
  2. Send crafted URL to victim
  3. If victim clicks → their code returned to attacker's session
  4. Attacker links victim's external account to attacker's app account
  → Account takeover / privilege escalation
```

```http
# Vulnerable: no state parameter
GET /oauth/authorize?client_id=X&redirect_uri=app.com/callback&response_type=code

# Check: drop state, does auth still complete?
```

---

## Attack 3: Authorization Code Leakage

```
Sources where auth codes leak:
  1. Referer header (HTTPS → HTTP downgrade)
  2. Browser history
  3. Proxy logs
  4. Access logs on redirect_uri server
  5. Analytics/tracking pixels loaded after redirect

Test: Is the code in a query parameter? (?code=ABC)
      Is the page after redirect loading any external resources?
      Those external requests carry Referer: ...?code=ABC
```

---

## Attack 4: Token Scope Escalation

```http
# Request token with minimal scope
POST /oauth/token
{
  "grant_type": "authorization_code",
  "code": "ABC",
  "scope": "read:profile"
}

# Add more scopes than authorized:
{
  "grant_type": "authorization_code", 
  "code": "ABC",
  "scope": "read:profile write:admin delete:users"
}
# If server grants all requested scopes without validating against
# what user actually consented to → scope escalation
```

---

## Attack 5: Implicit Flow Token in Fragment

```
Implicit flow (legacy, still common):
  Auth server redirects to: app.com/callback#access_token=TOKEN

Risk: Fragment is never sent to server — BUT:
  - If JavaScript on the callback page sends fragment to analytics
  - If there's an open redirect on callback page
  - If page loads external scripts that can read location.hash
→ Token stolen
```

---

## Attack 6: JWT Access Token Attacks

```
Most modern OAuth implementations use JWT access tokens.
Apply all JWT attack vectors from [[JWT-Misconfiguration]]:
  - alg:none
  - RS256→HS256 confusion  
  - Scope claim manipulation
  - Role claim injection

Additionally test:
  - Token for one client_id accepted by another resource server?
  - Token audience (aud) not validated?
  - Token issued for User A accepted when calling User B's resources?
```

---

## Attack 7: PKCE Bypass (Mobile/SPA)

```
PKCE (Proof Key for Code Exchange) prevents code interception.

Bypass when:
  - Server accepts requests without PKCE even when PKCE was started
  - code_verifier not validated against code_challenge
  - Downgrade: send PKCE request, exchange code without verifier

Test:
  1. Start PKCE flow (generate code_verifier + code_challenge)
  2. Get authorization code
  3. Exchange code WITHOUT code_verifier
  4. If access_token returned → PKCE not enforced
```

---

## SAML BAC Vulnerabilities

```xml
<!-- SAML Response includes role assertion -->
<Attribute Name="Role">
  <AttributeValue>user</AttributeValue>
</Attribute>

<!-- If signature only covers part of the assertion: -->
<!-- SAML Signature Wrapping (XSW) Attack:           -->
<!-- Move signed assertion, inject unsigned copy     -->
<Attribute Name="Role">
  <AttributeValue>admin</AttributeValue>  ← injected, unsigned
</Attribute>

<!-- XXE in SAML -->
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:AuthnRequest>...&xxe;...</samlp:AuthnRequest>
```

---

## OAuth Testing Tools

```bash
# Burp Suite OAuth scanner (built-in in Pro)
# Extensions: OAuth Tester (BApp Store)

# Manual testing checklist:
# 1. Note all OAuth parameters in auth request
# 2. Try redirect_uri manipulations in Burp Repeater
# 3. Remove state param — test for CSRF
# 4. Capture code — check if reusable
# 5. Test scope escalation in token request
# 6. Decode JWT access token — test claims

# jwt_tool for access token attacks:
python3 jwt_tool.py ACCESS_TOKEN -T
```

---

## Tasks
- [ ] #task Map the OAuth flow: capture all 4 steps in Burp
- [ ] #task Test redirect_uri with 8 manipulation variants
- [ ] #task Remove state parameter — check if OAuth CSRF possible
- [ ] #task Test scope escalation in token request
- [ ] #task Decode access token — is it JWT? Apply JWT attacks
- [ ] #task Check Referer leakage of authorization code
- [ ] #task If PKCE used, test exchange without code_verifier
- [ ] #task Check SAML responses if SSO is SAML-based

---

## 🔗 Related Notes
- [[JWT-Misconfiguration]]
- [[Horizontal-vs-Vertical]]
- [[API-BAC]]
- [[Testing-Checklist]]

---
*Tags: #oauth #sso #saml #bac #theory*
