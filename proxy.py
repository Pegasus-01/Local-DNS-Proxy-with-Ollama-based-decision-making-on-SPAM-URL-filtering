#!/usr/bin/env python3
"""
AI Ad-Block DNS Proxy
======================
Intercepts DNS queries, decides BLOCK or ALLOW using:
  1. Manual blocklist/allowlist (instant, highest priority)
  2. Static known-ad-network patterns (instant)
  3. In-memory decision cache (instant, 1hr TTL)
  4. Ollama LLM (2-10s, then cached)

All files live flat in this same folder:
  proxy.py            <- this file
  decisions.jsonl      <- live decision log (read by dashboard)
  proxy.log            <- human-readable log
  allowlist.json        <- manual allow overrides
  blocklist.json         <- manual block overrides
"""

import asyncio
import json
import logging
import re
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp

# ══════════════════════════════════════════════════════════════════════════
# CONFIG — edit these to taste
# ══════════════════════════════════════════════════════════════════════════

LISTEN_HOST   = "127.0.0.1"
LISTEN_PORT   = 5353              # iptables redirects system port 53 here
UPSTREAM_DNS  = "8.8.8.8"
UPSTREAM_PORT = 53

OLLAMA_URL    = "http://localhost:11434/api/generate"
OLLAMA_MODEL  = "mistral"          # MUST match `ollama list` exactly
OLLAMA_TIMEOUT_SECONDS = 30         # mistral cold-load can take 10+s

CACHE_SIZE = 2000
CACHE_TTL  = 3600                  # seconds before re-asking AI about a domain

# Junk suffixes some routers/ISPs append to local DNS searches — stripped
# before evaluation so the AI sees the real domain, not garbage like
# "ads.mozilla.org.attlocal.net"
JUNK_SUFFIXES = (".attlocal.net", ".home", ".lan", ".local")

# ══════════════════════════════════════════════════════════════════════════
# FILE PATHS — all flat, next to this script
# ══════════════════════════════════════════════════════════════════════════

HERE          = Path(__file__).parent
LOG_FILE      = HERE / "proxy.log"
DECISION_DB   = HERE / "decisions.jsonl"
ALLOWLIST     = HERE / "allowlist.json"
BLOCKLIST     = HERE / "blocklist.json"

# ══════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("ai-adblock")

# ══════════════════════════════════════════════════════════════════════════
# STATIC PATTERNS — fast-path, no AI needed
# ══════════════════════════════════════════════════════════════════════════

STATIC_BLOCK_PATTERNS = [
    r"(^|\.)(doubleclick|googlesyndication|googleadservices)\.com$",
    r"(^|\.)ads?\.(google|amazon|facebook|twitter|linkedin)\.com$",
    r"(^|\.)adnxs\.com$",
    r"(^|\.)adsrvr\.org$",
    r"(^|\.)adroll\.com$",
    r"(^|\.)moatads\.com$",
    r"(^|\.)rubiconproject\.com$",
    r"(^|\.)openx\.(com|net)$",
    r"(^|\.)pubmatic\.com$",
    r"(^|\.)scorecardresearch\.com$",
    r"(^|\.)quantserve\.com$",
    r"(^|\.)outbrain\.com$",
    r"(^|\.)taboola\.com$",
    r"(^|\.)criteo\.(com|net)$",
    r"(^|\.)amazon-adsystem\.com$",
    r"(^|\.)media\.net$",
    r"(^|\.)advertising\.com$",
    r"(^|\.)casalemedia\.com$",
    r"(^|\.)lijit\.com$",
    r"(^|\.)contextweb\.com$",
    r"(^|\.)appnexus\.com$",
    r"(^|\.)smartadserver\.com$",
    r"(^|\.)spotxchange\.com$",
    r"(^|\.)33across\.com$",
    r"(^|\.)sharethrough\.com$",
    r"(^|\.)chartbeat\.(com|net)$",
]

STATIC_ALLOW_PATTERNS = [
    r"(^|\.)google\.com$",
    r"(^|\.)googleapis\.com$",
    r"(^|\.)gstatic\.com$",
    r"(^|\.)github\.com$",
    r"(^|\.)githubusercontent\.com$",
    r"(^|\.)stackoverflow\.com$",
    r"(^|\.)ubuntu\.com$",
    r"(^|\.)debian\.org$",
    r"(^|\.)pypi\.org$",
    r"(^|\.)npmjs\.com$",
    r"(^|\.)cloudflare\.com$",
    r"(^|\.)cloudfront\.net$",
    r"(^|\.)fastly\.net$",
    r"(^|\.)akamaized\.net$",
    r"(^|\.)mozilla\.(com|org)$",
    r"(^|\.)mozilla\.net$",
]

_BLOCK_RE = [re.compile(p) for p in STATIC_BLOCK_PATTERNS]
_ALLOW_RE = [re.compile(p) for p in STATIC_ALLOW_PATTERNS]


def clean_domain(domain: str) -> str:
    """Strip junk router/ISP suffixes so the AI sees the real domain."""
    d = domain.lower().rstrip(".")
    for suffix in JUNK_SUFFIXES:
        if d.endswith(suffix):
            return d[: -len(suffix)]
    return d


def load_json_list(path: Path) -> set:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()))
    except Exception:
        return set()


def static_verdict(domain: str) -> Optional[str]:
    """Returns 'BLOCK', 'ALLOW', or None (defer to AI). Manual lists win."""
    d = domain.lower().rstrip(".")
    if d in load_json_list(ALLOWLIST):
        return "ALLOW"
    if d in load_json_list(BLOCKLIST):
        return "BLOCK"
    for pat in _BLOCK_RE:
        if pat.search(d):
            return "BLOCK"
    for pat in _ALLOW_RE:
        if pat.search(d):
            return "ALLOW"
    return None


# ══════════════════════════════════════════════════════════════════════════
# DECISION CACHE
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class CacheEntry:
    verdict: str
    reason: str
    timestamp: float = field(default_factory=time.time)

    def is_fresh(self) -> bool:
        return (time.time() - self.timestamp) < CACHE_TTL


class LRUDecisionCache:
    def __init__(self, maxsize: int = CACHE_SIZE):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._maxsize = maxsize

    def get(self, domain: str) -> Optional[CacheEntry]:
        entry = self._cache.get(domain)
        if entry is None:
            return None
        if not entry.is_fresh():
            del self._cache[domain]
            return None
        self._cache.move_to_end(domain)
        return entry

    def set(self, domain: str, entry: CacheEntry):
        self._cache[domain] = entry
        self._cache.move_to_end(domain)
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)


ai_cache = LRUDecisionCache()

# ══════════════════════════════════════════════════════════════════════════
# OLLAMA AI DECISION
# ══════════════════════════════════════════════════════════════════════════

AI_PROMPT = """You are a network security filter deciding whether to BLOCK or ALLOW a DNS query.

BLOCK: advertising networks, ad servers, tracking pixels, analytics beacons, \
telemetry endpoints, known malware/phishing domains, cryptomining scripts.
ALLOW: everything else — legitimate websites, CDNs serving real content, APIs, \
package registries, OS update servers.

Domain to evaluate: {domain}

Respond ONLY with valid JSON, no markdown, no extra text:
{{"verdict": "BLOCK" or "ALLOW", "reason": "one short sentence"}}"""


async def ask_ollama(session: aiohttp.ClientSession, domain: str) -> CacheEntry:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": AI_PROMPT.format(domain=domain),
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 80},
    }
    raw = ""
    try:
        async with session.post(
            OLLAMA_URL, json=payload,
            timeout=aiohttp.ClientTimeout(total=OLLAMA_TIMEOUT_SECONDS),
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                log.warning(f"Ollama HTTP {resp.status} for {domain}: {text[:200]!r}")
                return CacheEntry(verdict="ALLOW", reason=f"ollama_http_{resp.status}")

            body = await resp.json()
            raw = body.get("response", "").strip()

            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                log.warning(f"No JSON in Ollama response for {domain}: {raw[:200]!r}")
                return CacheEntry(verdict="ALLOW", reason="parse_error")

            parsed = json.loads(match.group(0))
            verdict = str(parsed.get("verdict", "ALLOW")).upper()
            if verdict not in ("BLOCK", "ALLOW"):
                verdict = "ALLOW"
            return CacheEntry(verdict=verdict, reason=str(parsed.get("reason", "")))

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.warning(f"Ollama unreachable/timeout for {domain}: {type(e).__name__}: {e}")
        return CacheEntry(verdict="ALLOW", reason="ollama_unreachable")
    except (json.JSONDecodeError, KeyError) as e:
        log.warning(f"Bad Ollama response for {domain}: {e} — raw: {raw[:200]!r}")
        return CacheEntry(verdict="ALLOW", reason="parse_error")


# ══════════════════════════════════════════════════════════════════════════
# DNS PACKET HELPERS
# ══════════════════════════════════════════════════════════════════════════

def parse_domain_from_query(data: bytes) -> Optional[str]:
    try:
        idx, labels = 12, []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            labels.append(data[idx: idx + length].decode("ascii", errors="replace"))
            idx += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


def build_nxdomain_response(query: bytes) -> bytes:
    txid = query[:2]
    flags = b"\x81\x83"   # QR=1 response, RCODE=3 NXDOMAIN
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    question = query[12:]
    return txid + flags + counts + question


async def forward_dns(query: bytes) -> bytes:
    loop = asyncio.get_event_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        await loop.run_in_executor(None, lambda: sock.sendto(query, (UPSTREAM_DNS, UPSTREAM_PORT)))
        try:
            response, _ = await loop.run_in_executor(None, lambda: sock.recvfrom(4096))
            return response
        except socket.timeout:
            return build_nxdomain_response(query)


# ══════════════════════════════════════════════════════════════════════════
# DECISION ENGINE
# ══════════════════════════════════════════════════════════════════════════

def log_decision(original_domain: str, evaluated_domain: str, verdict: str, reason: str, source: str):
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "domain": evaluated_domain,
        "original_domain": original_domain,
        "verdict": verdict,
        "reason": reason,
        "source": source,
    }
    with open(DECISION_DB, "a") as f:
        f.write(json.dumps(entry) + "\n")
    icon = "🚫" if verdict == "BLOCK" else "✅"
    log.info(f"{icon} [{source:8s}] {verdict:5s}  {evaluated_domain}  — {reason}")


async def decide(session: aiohttp.ClientSession, raw_domain: str) -> str:
    domain = clean_domain(raw_domain)

    sv = static_verdict(domain)
    if sv == "BLOCK":
        log_decision(raw_domain, domain, "BLOCK", "manual/static blocklist", "static")
        return "BLOCK"
    if sv == "ALLOW":
        log_decision(raw_domain, domain, "ALLOW", "manual/static allowlist", "static")
        return "ALLOW"

    cached = ai_cache.get(domain)
    if cached:
        log_decision(raw_domain, domain, cached.verdict, cached.reason, "cache")
        return cached.verdict

    entry = await ask_ollama(session, domain)
    ai_cache.set(domain, entry)
    log_decision(raw_domain, domain, entry.verdict, entry.reason, "ollama")
    return entry.verdict


# ══════════════════════════════════════════════════════════════════════════
# UDP SERVER
# ══════════════════════════════════════════════════════════════════════════

class DNSProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        domain = parse_domain_from_query(data)
        if not domain:
            self.transport.sendto(await forward_dns(data), addr)
            return

        verdict = await decide(self.session, domain)
        if verdict == "BLOCK":
            self.transport.sendto(build_nxdomain_response(data), addr)
        else:
            self.transport.sendto(await forward_dns(data), addr)


# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

async def main():
    log.info(f"Starting AI Ad-Block DNS Proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"Ollama model: {OLLAMA_MODEL}  |  Upstream DNS: {UPSTREAM_DNS}  |  Timeout: {OLLAMA_TIMEOUT_SECONDS}s")

    async with aiohttp.ClientSession() as session:
        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSProxyProtocol(session),
            local_addr=(LISTEN_HOST, LISTEN_PORT),
        )
        log.info("Proxy running. Press Ctrl+C to stop.")
        try:
            await asyncio.sleep(float("inf"))
        finally:
            transport.close()


if __name__ == "__main__":
    asyncio.run(main())
