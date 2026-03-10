---
tags: [bac, resources, labs, practice, portswigger]
type: resources
date: 2026-03-10
---

# 🧪 Practice Labs — BAC Hands-On Training

## PortSwigger Web Security Academy (FREE — Best BAC Labs)
```
URL: https://portswigger.net/web-security/access-control

Labs by difficulty:

APPRENTICE:
  ✅ Unprotected admin functionality
  ✅ Unprotected admin functionality with unpredictable URL
  ✅ User role controlled by request parameter
  ✅ User role can be modified in user profile
  ✅ URL-based access control can be circumvented
  ✅ Method-based access control can be circumvented
  
PRACTITIONER:
  ✅ User ID controlled by request parameter
  ✅ User ID controlled by request parameter, with unpredictable user IDs
  ✅ User ID controlled by request parameter with data leakage in redirect
  ✅ User ID controlled by request parameter with password disclosure
  ✅ Insecure direct object references
  ✅ Multi-step process with no access control on one step
  ✅ Referer-based access control
  
EXPERT:
  ✅ Multi-step process with no access control
  ✅ OAuth 2.0 access control bypass
```

## DVWA (Damn Vulnerable Web Application)
```
Install: docker run --rm -it -p 80:80 vulnerables/web-dvwa
Modules: Authorization Bypass, IDOR
URL: http://localhost/dvwa
```

## HackTheBox — BAC Focused Machines
```
Starting Point:
  - Archetype (Windows, priv escalation via misconfiguration)
  - Included (LFI → priv escalation)

Medium/Hard:
  - Horizontall (Mass assignment via Node.js)
  - Pandora (API BAC flaws)
  
Search filter: https://app.hackthebox.com/machines?tag=web
```

## TryHackMe Rooms
```
https://tryhackme.com/r/room/owasp10
  → Task: Broken Access Control section

https://tryhackme.com/r/room/owasptop102021
  → Challenge labs for each OWASP category

https://tryhackme.com/r/room/insecuredirectobjectreference
  → Dedicated IDOR room
```

## OWASP WebGoat
```
Install: docker run -p 8080:8080 -p 9090:9090 webgoat/goat-and-wolf
URL: http://localhost:8080/WebGoat
Modules:
  → Access Control Flaws (multiple lessons)
  → IDOR
  → JWT Attacks
```

## crAPI (Completely Ridiculous API)
```
# Purpose-built API security lab
Install: 
  git clone https://github.com/OWASP/crAPI
  cd crAPI && docker-compose up

Covers:
  - BOLA (IDOR for APIs)
  - BFLA (Function-level auth)
  - Mass assignment
  - JWT attacks
  - And more OWASP API Top 10
  
URL: http://localhost:8888
Mailhog: http://localhost:8025
```

## VAmPI
```
# Vulnerable API specifically for OWASP API Top 10
git clone https://github.com/erev0s/VAmPI
cd VAmPI && pip install -r requirements.txt
python3 app.py

Covers BOLA, mass assignment, excessive data exposure
```

## CTF Platforms with BAC Challenges
```
PicoCTF: https://play.picoctf.org
  → Web category, filter for "access control"

CTFlearn: https://ctflearn.com
  → Web security, BAC challenges

HackTheBox CTF (seasonal)
  → Web challenges category
```

---

## Structured Practice Plan

### Week 1 — Foundations
```
Day 1-2: PortSwigger - All Apprentice labs
Day 3-4: WebGoat - Access Control module
Day 5-7: DVWA - Authorization module
```

### Week 2 — IDOR Deep Dive
```
Day 1-3: PortSwigger - All IDOR Practitioner labs
Day 4-5: crAPI - BOLA and BFLA challenges
Day 6-7: VAmPI - Complete all challenges
```

### Week 3 — Advanced Techniques
```
Day 1-2: PortSwigger - Expert labs
Day 3-4: HackTheBox - BAC-themed machines
Day 5-7: TryHackMe - OWASP rooms
```

---

## Tasks
- [ ] #task Complete all PortSwigger Apprentice BAC labs
- [ ] #task Complete all PortSwigger Practitioner BAC labs
- [ ] #task Set up crAPI locally and solve all BOLA/BFLA challenges
- [ ] #task Complete WebGoat access control module
- [ ] #task Attempt 2 HackTheBox machines with BAC themes

---

## 🔗 Related Notes
- [[Write-Ups]]
- [[Testing-Checklist]]
- [[BAC-Overview]]

---
*Tags: #labs #practice #bac #portswigger #training*
