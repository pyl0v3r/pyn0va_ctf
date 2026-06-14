# PyNova

A vulnerable-by-design CTF machine built around a realistic web application attack chain — from initial reconnaissance to root.

> Published on [TryHackMe](https://tryhackme.com/room/pyn0va) <!-- replace # with your room link -->

## Overview

PyNova simulates a small business web platform exposing multiple services. The goal is to enumerate the application, gain an initial foothold via authenticated access, escalate to remote code execution, and pivot to root.

**Difficulty:** Medium
**OS:** Linux (Ubuntu Server)

## Skills Tested

- Service and web application enumeration (Rustscan, manual recon)
- Source code review for hidden endpoints
- Username enumeration from public-facing content
- Custom wordlist generation (John the Ripper rules)
- Credential brute-forcing with fuzzing tools (ffuf) against non-standard HTTP status codes
- Exploiting unrestricted file upload for remote code execution
- Linux privilege escalation via SUID/sudo misconfiguration

## Exposed Services

| Port | Service   |
|------|-----------|
| 21   | FTP       |
| 80   | HTTP      |
| 443  | HTTPS     |
| 3306 | MySQL     |
| 8000 | HTTP-alt  |

## Attack Path (High Level)

1. **Enumeration** — Scan exposed services and explore the web application on port 8000.
2. **Information Gathering** — Identify valid usernames and a hidden admin path via page source review.
3. **Credential Access** — Generate a targeted wordlist and brute-force authentication.
4. **Initial Foothold → RCE** — Exploit an unrestricted file upload vulnerability to achieve remote code execution.
5. **Privilege Escalation** — Escalate from a low-privilege service account to root.

## Flag Format

```
PY{...}
```

## Writeup

A full step-by-step walkthrough, including commands, payloads, and screenshots, is available here:

**[WRITEUP.md](./writeup/writeup.md)**

## Disclaimer

This machine was built for educational purposes as part of security research and CTF practice. All vulnerabilities are intentional and contained within the lab environment.