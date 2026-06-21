#!/usr/bin/env python3
"""
AI Ad-Block Dashboard Server
=============================
Serves the live web dashboard at http://localhost:8080

Reads decisions.jsonl / allowlist.json / blocklist.json / proxy.log
from the SAME folder this script lives in (flat structure, no env vars needed).
"""

import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

HERE         = Path(__file__).parent
DECISION_DB  = HERE / "decisions.jsonl"
ALLOWLIST    = HERE / "allowlist.json"
BLOCKLIST    = HERE / "blocklist.json"
LOG_FILE     = HERE / "proxy.log"
STATIC_DIR   = HERE / "dashboard_static"

app = Flask(__name__, static_folder=str(STATIC_DIR))
CORS(app)


# ── helpers ───────────────────────────────────────────────────────────────────
def load_entries(limit: int = 10000) -> list[dict]:
    if not DECISION_DB.exists():
        return []
    lines = DECISION_DB.read_text(errors="replace").splitlines()
    out = []
    for line in reversed(lines[-limit:]):
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out  # newest first


def load_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def save_list(path: Path, items):
    path.write_text(json.dumps(sorted(set(items)), indent=2))


# ── API: stats ────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    entries = load_entries()
    total   = len(entries)
    blocked = sum(1 for e in entries if e.get("verdict") == "BLOCK")
    allowed = total - blocked
    sources = Counter(e.get("source", "?") for e in entries)

    top_blocked = Counter(e["domain"] for e in entries if e.get("verdict") == "BLOCK").most_common(10)
    top_allowed = Counter(e["domain"] for e in entries if e.get("verdict") == "ALLOW").most_common(10)

    now = time.time()
    hourly = {}
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["ts"]).timestamp()
        except Exception:
            continue
        age_h = int((now - ts) / 3600)
        if age_h > 23:
            continue
        h = 23 - age_h
        b = hourly.setdefault(h, {"block": 0, "allow": 0})
        b["block" if e.get("verdict") == "BLOCK" else "allow"] += 1

    timeline = [{"hour": h, **hourly.get(h, {"block": 0, "allow": 0})} for h in range(24)]

    return jsonify({
        "total": total, "blocked": blocked, "allowed": allowed,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "sources": dict(sources),
        "top_blocked": [{"domain": d, "count": c} for d, c in top_blocked],
        "top_allowed": [{"domain": d, "count": c} for d, c in top_allowed],
        "timeline": timeline,
    })


# ── API: decisions (paginated, searchable) ────────────────────────────────────
@app.route("/api/decisions")
def api_decisions():
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    search   = request.args.get("search", "").strip().lower()
    verdict  = request.args.get("verdict", "").upper()
    source   = request.args.get("source", "").lower()

    entries = load_entries()
    if search:
        entries = [e for e in entries if search in e.get("domain", "").lower()
                                      or search in e.get("reason", "").lower()]
    if verdict in ("BLOCK", "ALLOW"):
        entries = [e for e in entries if e.get("verdict") == verdict]
    if source:
        entries = [e for e in entries if source in e.get("source", "").lower()]

    total = len(entries)
    page_entries = entries[(page - 1) * per_page: page * per_page]

    return jsonify({
        "total": total, "page": page, "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
        "entries": page_entries,
    })


# ── API: allowlist ────────────────────────────────────────────────────────────
@app.route("/api/allowlist", methods=["GET"])
def get_allowlist():
    return jsonify(load_list(ALLOWLIST))


@app.route("/api/allowlist", methods=["POST"])
def add_allowlist():
    domain = request.json.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    items = load_list(ALLOWLIST)
    if domain not in items:
        items.append(domain)
        save_list(ALLOWLIST, items)
    save_list(BLOCKLIST, [x for x in load_list(BLOCKLIST) if x != domain])
    return jsonify({"ok": True, "domain": domain})


@app.route("/api/allowlist/<path:domain>", methods=["DELETE"])
def remove_allowlist(domain):
    save_list(ALLOWLIST, [x for x in load_list(ALLOWLIST) if x != domain])
    return jsonify({"ok": True})


# ── API: blocklist ────────────────────────────────────────────────────────────
@app.route("/api/blocklist", methods=["GET"])
def get_blocklist():
    return jsonify(load_list(BLOCKLIST))


@app.route("/api/blocklist", methods=["POST"])
def add_blocklist():
    domain = request.json.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    items = load_list(BLOCKLIST)
    if domain not in items:
        items.append(domain)
        save_list(BLOCKLIST, items)
    save_list(ALLOWLIST, [x for x in load_list(ALLOWLIST) if x != domain])
    return jsonify({"ok": True, "domain": domain})


@app.route("/api/blocklist/<path:domain>", methods=["DELETE"])
def remove_blocklist(domain):
    save_list(BLOCKLIST, [x for x in load_list(BLOCKLIST) if x != domain])
    return jsonify({"ok": True})


# ── API: raw log tail ──────────────────────────────────────────────────────────
@app.route("/api/log")
def api_log():
    n = int(request.args.get("n", 100))
    if not LOG_FILE.exists():
        return jsonify({"lines": []})
    lines = LOG_FILE.read_text(errors="replace").splitlines()
    return jsonify({"lines": lines[-n:]})


# ── static frontend ────────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path and (STATIC_DIR / path).exists():
        return send_from_directory(str(STATIC_DIR), path)
    return send_from_directory(str(STATIC_DIR), "index.html")


if __name__ == "__main__":
    print("🛡️  AI Ad-Block Dashboard")
    print(f"   Reading data from: {HERE}")
    print("   Open: http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
