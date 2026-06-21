# 🛡️ AI Ad-Block — Local DNS Proxy with LLM-Based Filtering

*This project is strictly for personal use/learning. Do not use it in any production environment.
*This is still in the last stages of development, which might cause some errors to occur - once all fixed, this disclaimer will be removed.
A self-hosted DNS proxy that sits between your machine and the internet, using a **locally-run LLM (via Ollama)** to decide — in real time — whether a domain should be blocked (ads, trackers, analytics, telemetry) or allowed.

Comes with a live web dashboard to monitor traffic, search the decision log, and manage manual allow/block overrides.

No data ever leaves your machine. No cloud APIs. No telemetry of your own.

---

## How it works

```
Your browser / app
      │  DNS query (port 53)
      ▼
iptables NAT redirect
      │  → port 5353
      ▼
┌────────────────────────────────────────┐
│              proxy.py                  │
│                                        │
│  1. Manual allowlist/blocklist check   │ ← instant
│  2. Static ad-network pattern match    │ ← instant
│  3. In-memory decision cache (1h TTL)  │ ← instant
│  4. Ask Ollama (LLM)                   │ ← ~1-10s, then cached
│                                        │
│  BLOCK → NXDOMAIN                      │
│  ALLOW → forward to 8.8.8.8            │
└────────────────────────────────────────┘
      │
      ▼
 decisions.jsonl + proxy.log
      │
      ▼
┌────────────────────────────────────────┐
│            dashboard.py                │
│   Flask server reading the same files  │
│   → live web UI at localhost:8080      │
└────────────────────────────────────────┘
```

Every query is logged with its domain, verdict, reason, and which layer made the decision (`static`, `cache`, or `ollama`) — all visible live in the dashboard.

---

## Project structure

Flat by design — everything lives in one folder, no nested config to lose track of.

```
adblock/
├── proxy.py                 # DNS proxy + AI decision engine — run this to filter traffic
├── dashboard.py               # Flask web server — run this for the live UI
├── dashboard_static/
│   └── index.html             # dashboard frontend (HTML/CSS/JS, single file)
├── setup-iptables.sh           # toggles system-wide DNS redirect on/off
├── requirements.txt             # pip dependencies for both proxy + dashboard
├── allowlist.json                 # manual ALLOW overrides (edit directly or via dashboard)
├── blocklist.json                  # manual BLOCK overrides (edit directly or via dashboard)
├── decisions.jsonl                   # auto-generated live decision log (dashboard reads this)
└── proxy.log                           # auto-generated human-readable log
```

---

## Requirements

- Linux (tested on Ubuntu/Kali) with root/sudo access
- Python 3.10+
- [Ollama](https://ollama.com) installed locally
- ~2–5 GB free RAM depending on model choice
- `iptables`

---

## Installation

### 1. Install Ollama and pull a model

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
```

Pick a model based on your hardware. **Smaller models respond faster and more reliably to the structured JSON output this project requires** — bigger isn't always better here.

```bash
ollama pull llama3.2:1b      # recommended: fastest, most reliable JSON output
# or
ollama pull llama3.2:3b      # a bit smarter, still fast
# or
ollama pull mistral          # heavier, slower — only if you have RAM/CPU to spare
```

Confirm the exact name Ollama registered:
```bash
ollama list
```

### 2. Clone/copy this project

```bash
sudo cp -r adblock /opt/adblock
cd /opt/adblock
```

### 3. Set up the Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Point the proxy at your model

Open `proxy.py` and make sure this line matches exactly what `ollama list` showed:

```python
OLLAMA_MODEL = "llama3.2:1b"
```

### 5. Free up the ports the proxy needs

Ubuntu/Kali's `systemd-resolved` and `avahi-daemon` often occupy ports 53 and 5353 by default.

```bash
# Free port 5353 (avahi/mDNS)
sudo systemctl stop avahi-daemon.socket avahi-daemon
sudo systemctl disable avahi-daemon.socket avahi-daemon

# Free port 53 (systemd-resolved stub listener)
sudo sed -i '/\[Resolve\]/a DNSStubListener=no' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# Confirm both are free
sudo ss -ulnp | grep ':53\b'
sudo ss -ulnp | grep 5353
```

---

## Running it

You need **two terminals** (or two background services) running at once.

### Terminal 1 — the proxy

```bash
cd /opt/adblock
source venv/bin/activate
python3 proxy.py
```

### Terminal 2 — test before going system-wide

```bash
dig @127.0.0.1 -p 5353 doubleclick.net   # expect NXDOMAIN (blocked)
dig @127.0.0.1 -p 5353 github.com        # expect a real IP (allowed)
```

### Once confirmed working, route all system DNS through it

```bash
sudo bash /opt/adblock/setup-iptables.sh add
dig google.com    # now silently passes through the AI filter
```

### Terminal 3 — the dashboard

```bash
cd /opt/adblock
source venv/bin/activate
python3 dashboard.py
```

Open **http://localhost:8080** in your browser.

---

## Using the dashboard

| Tab | What it shows |
|---|---|
| **Overview** | Live stat cards (total/blocked/allowed/AI-decided), 24-hour activity chart, decision-source breakdown, top blocked/allowed domains |
| **Decisions** | Full searchable, filterable, paginated log of every query — with one-click Allow/Block buttons per row |
| **Allow / Block** | Add or remove manual overrides directly; changes apply **immediately**, no restart needed |
| **Raw Log** | Live, colour-coded tail of `proxy.log` |

Manual overrides always take priority over the AI's decision and over the built-in static pattern list.

---

## Reverting everything (back to normal DNS)

```bash
# Stop both processes
pkill -f proxy.py
pkill -f dashboard.py

# Remove the DNS redirect — restores normal internet immediately
sudo bash /opt/adblock/setup-iptables.sh remove

# Re-enable avahi
sudo systemctl enable --now avahi-daemon.socket avahi-daemon

# Restore the systemd-resolved stub listener
sudo sed -i 's/DNSStubListener=no/DNSStubListener=yes/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# Verify
dig google.com
```

---

## Configuration reference

All tunables live at the top of `proxy.py`:

| Setting | Default | Purpose |
|---|---|---|
| `LISTEN_PORT` | `5353` | Where the proxy listens (iptables redirects 53 here) |
| `UPSTREAM_DNS` | `8.8.8.8` | Resolver used for ALLOWed queries |
| `OLLAMA_MODEL` | `mistral` | Must exactly match `ollama list` output |
| `OLLAMA_TIMEOUT_SECONDS` | `30` | How long to wait for a single Ollama response |
| `CACHE_TTL` | `3600` | Seconds before re-asking the AI about a domain |
| `JUNK_SUFFIXES` | `.attlocal.net`, etc. | Router/ISP suffixes stripped before evaluation |

---

## Troubleshooting

**Nothing resolves / internet is dead**
The iptables redirect is active but the proxy isn't running (or crashed). Immediately restore access:
```bash
sudo bash /opt/adblock/setup-iptables.sh remove
```
Then start `proxy.py` again and test with `dig @127.0.0.1 -p 5353 ...` before re-adding the redirect.

**Every decision logs `ollama_unreachable`**
- Check the model name in `proxy.py` matches `ollama list` *exactly* (including tag, e.g. `:1b`)
- Time a manual test call: `time curl -s http://localhost:11434/api/generate -d '{"model":"<your model>","prompt":"hi","stream":false}'` — if it's slower than `OLLAMA_TIMEOUT_SECONDS`, either raise the timeout or switch to a smaller/faster model
- A page load triggers many parallel DNS lookups; if Ollama processes them sequentially, later ones can time out waiting in line even if each individual response is fast. Smaller models reduce this bottleneck significantly.

**Decisions log `parse_error`**
The model isn't returning clean JSON — it's adding explanatory text around it. Smaller, instruction-tuned models (e.g. `llama3.2:1b`) tend to follow the strict JSON format more reliably than larger general-purpose models like `mistral` at default settings.

**Dashboard shows a 404 / blank page**
`index.html` must be at `/opt/adblock/dashboard_static/index.html` exactly. Confirm with:
```bash
find /opt/adblock -iname "*.html"
```

**Port already in use errors**
```bash
sudo ss -ulnp | grep 5353
sudo ss -ulnp | grep ':53\b'
```
Kill or disable whatever is shown (commonly `avahi-daemon` on 5353, `systemd-resolved` on 53).

---

## Security & privacy notes

- All DNS evaluation happens **locally** — no domain you visit is ever sent to a third party
- The static blocklist patterns are a known-network fast-path; the LLM is the fallback for anything not already categorized
- Manual allow/block lists always override the AI — useful for false positives or for permanently blocking something the model occasionally misjudges
- This is a personal/home-network tool, not hardened for multi-user or production deployment (the dashboard has no auth — don't expose port 8080 beyond your local network)
