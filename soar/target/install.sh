#!/usr/bin/env bash
# Phase 4: install the SOAR block-list on the target VM. Idempotent.
# Usage: sudo bash install.sh "<public key Shuffle will use>"
set -euo pipefail
cd "$(dirname "$0")"
PUBKEY=${1:?usage: install.sh "<ssh public key>"}

install -m 644 lab-block.nft /etc/lab-block.nft
install -m 755 lab-block.sh /usr/local/sbin/lab-block

# Load the table at boot. Not nftables.service: its default config does "flush ruleset", which wipes Docker's rules.
cat > /etc/systemd/system/lab-block.service <<'EOF'
[Unit]
Description=SOAR block-list (nftables table inet lab_block)
After=network-pre.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet lab_block
ExecStart=/usr/sbin/nft -f /etc/lab-block.nft
ExecStop=/usr/sbin/nft delete table inet lab_block

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable lab-block.service >/dev/null 2>&1
systemctl restart lab-block.service

# Dedicated user: no password, no shell use; its key can only run lab-block.
id soar >/dev/null 2>&1 || useradd --system --create-home --shell /bin/bash soar
passwd -l soar >/dev/null
install -d -m 700 -o soar -g soar /home/soar/.ssh
echo "command=\"/usr/local/sbin/lab-block\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,from=\"192.168.56.1\" $PUBKEY" \
  > /home/soar/.ssh/authorized_keys
chown soar:soar /home/soar/.ssh/authorized_keys
chmod 600 /home/soar/.ssh/authorized_keys

# sudo only for nft and appending to the log
cat > /etc/sudoers.d/soar <<'EOF'
soar ALL=(root) NOPASSWD: /usr/sbin/nft, /usr/bin/tee -a /var/log/lab-block.log
EOF
chmod 440 /etc/sudoers.d/soar
visudo -cf /etc/sudoers.d/soar >/dev/null

touch /var/log/lab-block.log
echo "lab-block installed"
nft list table inet lab_block
