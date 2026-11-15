#!/usr/bin/env bash
# Phase 2: Suricata IDS on the target VM (Ubuntu 26.04, Suricata 8).
# Idempotent: safe to re-run. Usage: sudo bash setup.sh [interface] [home_net]
set -euo pipefail

IFACE=${1:-enp0s3}                                   # lab (host-only) interface
HOME_NET=${2:-"[192.168.56.40/32,172.16.0.0/12]"}    # target + Docker; Kali must be OUTSIDE it
CONF=/etc/suricata/suricata.yaml

apt-get install -y -qq suricata jq >/dev/null
suricata-update -q                                    # ET Open rules -> /var/lib/suricata/rules/suricata.rules

[ -f "$CONF.orig" ] || cp "$CONF" "$CONF.orig"
cp "$CONF.orig" "$CONF"

# Rules with $EXTERNAL_NET only fire for sources outside HOME_NET.
# The default (all of 192.168.0.0/16) would make Kali "internal" and silence most scan rules.
sed -i "s#^\(\s*HOME_NET:\).*#\1 \"$HOME_NET\"#" "$CONF"

# Capture on the lab interface (default is eth0, which doesn't exist here)
sed -i "0,/^  - interface: eth0/s//  - interface: $IFACE/" "$CONF"

# Phase 5: log every request header in eve.json, so the ML model can see payloads hidden in
# User-Agent / Referer / Cookie (sqlmap --level 3 injects there; the URL alone looks clean)
sed -i 's/^\(\s*\)# dump-all-headers: none$/\1dump-all-headers: request/' "$CONF"
grep -q '^\s*dump-all-headers: request$' "$CONF" || { echo "could not enable dump-all-headers"; exit 1; }

# Extra, alerts-only EVE file for Wazuh; the full eve.json stays for the ML phase
sed -i '/^outputs:/a\
  - eve-log:\
      enabled: yes\
      filetype: regular\
      filename: eve-alerts.json\
      community-id: true\
      types:\
        - alert:\
            metadata: yes\
            payload-printable: yes' "$CONF"

suricata -T -c "$CONF" -v 2>&1 | tail -3              # config test (loads all rules, ~1 min)
[ "${PIPESTATUS[0]}" -eq 0 ]
systemctl enable suricata >/dev/null 2>&1
systemctl restart suricata
echo "Suricata listening on $IFACE, HOME_NET=$HOME_NET"
