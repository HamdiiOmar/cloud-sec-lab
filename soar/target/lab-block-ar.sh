#!/usr/bin/env bash
# Phase 4: Wazuh Active Response wrapper around /usr/local/sbin/lab-block.
# Installed on the target as /var/ossec/active-response/bin/lab-block.sh and run by the Wazuh agent (as root).
# Wazuh 4.x passes one JSON message on stdin, e.g. from the API:
#   {"command":"add","parameters":{"extra_args":["192.168.56.103","10"],"alert":{...}}}
# The IP comes from extra_args[0] (Shuffle) or the alert's srcip / client_ip / src_ip fields (rule-triggered).
# Stateless: the nftables set expires entries itself, so there is no "delete" step.
set -uo pipefail
LOG=/var/ossec/logs/active-responses.log

read -r INPUT
CMD=$(jq -r '.command // empty' <<< "$INPUT")
IP=$(jq -r '
	.parameters.extra_args[0]
	// .parameters.alert.data.srcip
	// .parameters.alert.data.transaction.client_ip
	// .parameters.alert.data.src_ip
	// empty' <<< "$INPUT")
MINUTES=$(jq -r '.parameters.extra_args[1] // "10"' <<< "$INPUT")

echo "$(date '+%Y/%m/%d %H:%M:%S') lab-block-ar: command=$CMD ip=$IP minutes=$MINUTES" >> "$LOG"

[ "$CMD" = "add" ] || exit 0
[ -n "$IP" ] || { echo "$(date '+%Y/%m/%d %H:%M:%S') lab-block-ar: no IP in message" >> "$LOG"; exit 1; }

/usr/local/sbin/lab-block block "$IP" "$MINUTES" >> "$LOG" 2>&1
