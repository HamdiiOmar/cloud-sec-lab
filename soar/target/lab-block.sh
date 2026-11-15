#!/usr/bin/env bash
# Phase 4: the only command Shuffle's SSH key is allowed to run (forced command in authorized_keys).
# The requested command arrives in $SSH_ORIGINAL_COMMAND, e.g.:
#   block 192.168.56.103 [minutes]   unblock 192.168.56.103   list
set -euo pipefail

# Never block the lab's own infrastructure: the host (Shuffle, Prometheus) and the Wazuh manager.
PROTECTED="192.168.56.1 192.168.56.104 192.168.56.40 127.0.0.1"
LOG=/var/log/lab-block.log

read -r action ip minutes extra <<< "${SSH_ORIGINAL_COMMAND:-${*:-}}" || true
log() { echo "$(date -Is) $*" | sudo tee -a "$LOG" >/dev/null; }

valid_ip() {
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for o in "${BASH_REMATCH[@]:1}"; do ((o <= 255)) || return 1; done
}

case "${action:-}" in
	block)
		valid_ip "${ip:-}" || { echo "error: invalid IP"; exit 2; }
		for p in $PROTECTED; do [ "$ip" = "$p" ] && { log "REFUSED $ip (protected)"; echo "refused: $ip is protected"; exit 3; }; done
		minutes=${minutes:-10}
		[[ $minutes =~ ^[0-9]+$ ]] && ((minutes >= 1 && minutes <= 1440)) || { echo "error: minutes must be 1-1440"; exit 2; }
		# "add" on an existing element keeps the old timeout, so delete first to restart the ban
		sudo nft delete element inet lab_block blocklist "{ $ip }" 2>/dev/null || true
		sudo nft add element inet lab_block blocklist "{ $ip timeout ${minutes}m }"
		log "BLOCK $ip ${minutes}m"
		echo "blocked $ip for ${minutes}m"
		;;
	unblock)
		valid_ip "${ip:-}" || { echo "error: invalid IP"; exit 2; }
		sudo nft delete element inet lab_block blocklist "{ $ip }" 2>/dev/null && log "UNBLOCK $ip" && echo "unblocked $ip" || echo "$ip was not blocked"
		;;
	list)
		sudo nft -j list set inet lab_block blocklist
		;;
	*)
		echo "usage: block <ip> [minutes] | unblock <ip> | list"; exit 2
		;;
esac
