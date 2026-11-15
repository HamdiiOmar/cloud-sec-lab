#!/usr/bin/env bash
# Host-side recovery after a reboot. Runs at login via ~/.config/systemd/user/lab-up.service.
# Why: on this host VirtualBox's host-only interfaces are not recreated at boot (the vboxdrv.service
# left behind by an old Oracle VirtualBox install fails), so vboxnet0 / 192.168.56.1 is missing,
# VMs refuse to start, and Shuffle's backend (published on 192.168.56.1:5001) fails to start.
set -uo pipefail
LAB=$(cd "$(dirname "$0")/../.." && pwd)

if ! VBoxManage list hostonlyifs | grep -q '^Name: *vboxnet0$'; then
	VBoxManage hostonlyif create
	echo "created vboxnet0"
fi
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Shuffle's backend binds 192.168.56.1, so it must be (re)created after vboxnet0 exists
cd "$LAB/soar/shuffle" && docker compose up -d --force-recreate backend frontend
echo "lab host side ready"
