#!/usr/bin/env bash
# Redirects local DNS (port 53) to the proxy (port 5353).
# Usage:
#   sudo bash setup-iptables.sh add       <- start filtering all system DNS
#   sudo bash setup-iptables.sh remove    <- undo, back to normal DNS

set -euo pipefail
ACTION="${1:-add}"

if [[ "$ACTION" == "add" ]]; then
    echo "[+] Redirecting UDP/TCP port 53 → 5353..."
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353
    echo "[+] Done. All DNS from this machine now flows through the AI proxy."
elif [[ "$ACTION" == "remove" ]]; then
    echo "[-] Removing DNS redirect rules..."
    iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true
    echo "[-] Done. DNS is restored to normal."
else
    echo "Usage: $0 [add|remove]"
    exit 1
fi
