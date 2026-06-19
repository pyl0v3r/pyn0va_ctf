# PyNova — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of **PyNova**, a custom-built vulnerable-by-design machine (TryHackMe), simulating a realistic small business web platform. The goal was to identify and chain vulnerabilities across the web application layer and host configuration to achieve full root-level compromise.

## Scope of Work

**In-Scope Assets:**
- **Host:** 192.168.0.218
- **Services:** FTP (21), HTTP (80), HTTPS (443), MySQL (3306), HTTP-alt / Web Application (8000)
- **Testing Perspective:** Unauthenticated external attacker

---

## Enumeration

### Port Scan (Rustscan)

```
PORT     STATE  SERVICE
21/tcp   open   ftp
80/tcp   open   http
443/tcp  open   https
3306/tcp open   mysql
8000/tcp open   http-alt
```

### Web Application Enumeration (Port 8000)

Manual review of the web application on port 8000 revealed:

- A **Contact Us** page with a non-functional submit button — confirmed dead end
- An **Our Team** section listing staff names, useful for username enumeration
- A hidden `/admin` path discovered via page source review

### Tools Used
- Rustscan
- John the Ripper
- ffuf
- netcat

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| Username Enumeration via Public-Facing Staff Page | Low | Enables targeted credential attacks |
| No Brute-Force Protection on Login Endpoint | High | Credential discovery via fuzzing |
| Unrestricted File Upload Leading to Remote Code Execution | Critical | Full remote code execution as service account |
| Privilege Escalation via Misconfigured `sudo` on Python | Critical | Root-level access |

---

### Username Enumeration via Public-Facing Staff Page

#### Severity
Low

#### CWE
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The web application's "Our Team" section publicly lists staff names without restriction. These names were used to derive valid application usernames, providing a high-confidence target list for the credential brute-force attack described in the following finding.

Additionally, a hidden `/admin` path was found in the page source, confirming the presence of an administrative interface not linked from the navigation.

#### Affected Functionality
- "Our Team" page (port 8000)
- Page source of the web application

#### Steps to Reproduce
1. Browse to the web application on port 8000.
2. Locate the "Our Team" section and note all listed staff names.
3. View page source and search for commented-out or hidden paths.

#### Proof of Concept
The following valid usernames were derived from the staff listing:
```
pyl0v3r
r00t
and3rs
```
A hidden admin path was also identified in the page source:
```
/admin
```

#### Impact
- Provides a valid username list for credential attacks against the login endpoint
- Exposes an administrative interface path that would not otherwise be discoverable through normal navigation

#### Root Cause
Staff names are published on a public-facing page without consideration of how they map to application usernames. Administrative paths are referenced in client-side source without access control preventing discovery.

#### Recommendation
- Decouple publicly displayed staff names from internal account usernames
- Remove references to administrative paths from client-side HTML/source
- Protect the `/admin` path with authentication and consider moving it to a non-guessable path
- Implement security headers and enforce authentication before exposing any administrative functionality

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-200

---

### No Brute-Force Protection on Login Endpoint

#### Severity
High

#### CWE
CWE-307: Improper Restriction of Excessive Authentication Attempts

#### OWASP Category
OWASP Top 10 2021 – A07: Identification and Authentication Failures

#### Description
The login endpoint on port 8000 does not implement account lockout, rate-limiting, or CAPTCHA. This allowed an attacker to submit unlimited authentication attempts with a custom-generated wordlist, successfully recovering a valid credential. The endpoint returned HTTP 401 on failure, which required switching from Hydra (which struggles with non-200 failure codes) to ffuf using a filter-based approach, but posed no meaningful barrier to credential discovery.

#### Affected Functionality
- `POST /login` (port 8000)

#### Steps to Reproduce
1. Generate a custom wordlist using John the Ripper with Jumbo rules against a base wordlist, targeting likely password formats:
   ```bash
   ./john --wordlist=word_list.txt --rules=Jumbo --min-length=6 --max-length=12 --stdout > custom_wordlist.txt
   ```
2. Fuzz the login endpoint using ffuf, filtering out 401 responses to surface valid credentials:
   ```bash
   ffuf -w custom_wordlist.txt \
     -X POST \
     -d "username=pyl0v3r&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://192.168.0.218:8000/login \
     -fc 401
   ```
3. Observe a successful authentication response for a matching password.

#### Proof of Concept
ffuf returned a non-401 response for a specific password entry in the custom wordlist, confirming a valid credential for the `pyl0v3r` account. This credential was then used to authenticate to the web application.

#### Impact
- Valid credentials obtained for an application account
- Authenticated access granted, which was the prerequisite for the file upload functionality used to achieve RCE (see next finding)

#### Root Cause
The login endpoint processes unlimited requests without tracking or restricting authentication attempts per IP or account, and no secondary control (CAPTCHA, MFA) is in place to prevent automated attacks.

#### Recommendation
- Implement account lockout or progressive rate-limiting after a configurable number of failed attempts
- Apply per-IP rate-limiting at the web server or WAF layer
- Introduce CAPTCHA for repeated authentication failures
- Consider multi-factor authentication for all accounts with access to sensitive functionality

#### References
- OWASP Top 10 2021 – A07: Identification and Authentication Failures
- CWE-307

---

### Unrestricted File Upload Leading to Remote Code Execution

#### Severity
Critical

#### CWE
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-94: Improper Control of Generation of Code

#### OWASP Category
OWASP Top 10 2021 – A03: Injection

#### Description
Following authentication, the application exposed a file upload feature with no server-side validation of uploaded file types or content. A PHP reverse shell (pentestmonkey's `php-reverse-shell.php`) was uploaded directly without modification. The file was stored in a web-accessible directory and executed by the server when requested, resulting in a reverse shell connecting back to the attacker's listener.

#### Affected Functionality
- File upload feature (authenticated, port 8000)
- Web-accessible upload storage directory

#### Steps to Reproduce
1. Authenticate to the application using the credentials recovered via brute-force.
2. Navigate to the file upload feature.
3. Upload a PHP reverse shell (`shell.php`) configured with the attacker's IP and listener port (1337).
4. Start a netcat listener on the attacker machine:
   ```bash
   nc -lvnp 1337
   ```
5. Request the uploaded file through the browser to trigger execution.

#### Proof of Concept
Uploading `shell.php` and requesting it via the browser resulted in the following connection being established on the attacker's listener:

```
Connection received on 172.25.128.1 7608
Linux ubuntuserver 6.8.0-106-generic
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

This confirmed arbitrary PHP code execution on the server as the `daemon` service account.

#### Impact
- Full remote code execution as the `daemon` service account
- Provided a foothold on the underlying host, enabling the privilege escalation described below

#### Root Cause
The upload handler performs no validation of file type, extension, MIME type, or file content, and stores uploaded files in a directory where the web server will execute PHP. This is the combination of failures that makes file upload exploitation possible: accepting dangerous file types, and storing them where they can be executed.

#### Recommendation
- Restrict accepted file types to an explicit allow-list (e.g. images only) validated server-side on both extension and MIME type/file signature
- Store uploaded files outside the web root to prevent direct browser access
- Disable PHP (and script) execution in upload storage directories via server configuration (e.g. Apache `php_flag engine off` in `.htaccess`)
- Re-encode or process uploaded files server-side (e.g. re-save images via an image library) to strip any embedded executable content
- Authenticate and authorize access to uploaded files rather than serving them directly

#### References
- OWASP Top 10 2021 – A03: Injection
- CWE-434
- CWE-94
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

### Privilege Escalation via Misconfigured `sudo` on Python

#### Severity
Critical

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A05: Security Misconfiguration

#### Description
The `daemon` service account, obtained via the file upload RCE, was permitted to run `python3` with `sudo` without a password. Python provides trivial OS-level access via its standard library, allowing `os.setuid(0)` to change the effective UID to root followed by spawning an interactive shell — effectively bypassing all privilege separation. This is a well-documented GTFOBins primitive.

#### Affected Functionality
- `sudo python3` permissions for the `daemon` account

#### Steps to Reproduce
1. From the reverse shell (running as `daemon`), verify sudo permissions.
2. Execute the following one-liner to escalate to root:
   ```bash
   sudo python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
   ```
3. Confirm root access and retrieve the flag:
   ```bash
   cd /root && cat flag.txt
   ```

#### Proof of Concept
Running the Python one-liner as `daemon` produced an interactive bash session as `uid=0 (root)`. The root flag was retrieved:
```
PY{RCE_VIA_FILE_UPLOAD}
```

#### Impact
- Complete privilege escalation from a low-privilege service account to root
- Full compromise of host confidentiality, integrity, and availability

#### Root Cause
The `daemon` account has been granted `sudo` access to `python3` without restriction, likely as a convenience for a service or maintenance script. Python's standard library (`os` module) makes `setuid` and shell invocation trivial, meaning any `sudo python3` grant is effectively equivalent to granting unrestricted root access.

#### Recommendation
- Remove the `sudo python3` permission from the `daemon` account entirely
- If a specific script must run with elevated privileges, grant access only to that script path (not the interpreter itself), and sign/hash-verify it to prevent modification
- Audit all `sudoers` entries and cross-reference against GTFOBins to identify other dangerous interpreter or binary grants
- Run web-facing service accounts with minimal OS permissions and no `sudo` access

#### References
- OWASP Top 10 2021 – A05: Security Misconfiguration
- CWE-269
- [GTFOBins — Python](https://gtfobins.github.io/gtfobins/python/)

---

## Attack Chain Summary

1. Enumerated open services via Rustscan — identified a web application on port 8000
2. Discovered valid usernames via the "Our Team" page and a hidden `/admin` path in page source
3. Generated a custom wordlist with John the Ripper (Jumbo rules) and brute-forced the login with ffuf, filtering 401 responses to recover valid credentials
4. Authenticated and used the unrestricted file upload feature to upload a PHP reverse shell
5. Triggered execution of the uploaded shell by requesting it via the browser, establishing a reverse shell as `daemon`
6. Escalated to root by exploiting a `sudo python3` misconfiguration using a GTFOBins one-liner

## Key Takeaways

- Public staff pages are a practical username enumeration source — username design should not mirror publicly visible names
- Login endpoints without rate-limiting or lockout are trivially brute-forced, even when response codes differ from 200
- Unrestricted file upload combined with a web-accessible, PHP-executing storage directory is a direct path to RCE
- Granting `sudo` access to any scripting interpreter (Python, Perl, Ruby) is functionally equivalent to granting unrestricted root — always check against GTFOBins before assigning `sudo` permissions