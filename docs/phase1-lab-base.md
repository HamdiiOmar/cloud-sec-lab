# Phase 1: Lab base

Deliverable: an attack sent from Kali is blocked by the WAF and shows up as an alert in Wazuh.

## Network (VirtualBox host-only `vboxnet0`, 192.168.56.0/24)

| VM | IP | RAM | Role |
|---|---|---|---|
| Wazuh (official OVA) | 192.168.56.104 (DHCP) | 8 GB, 4 vCPU | Wazuh all-in-one (manager + indexer + dashboard) |
| Target (Ubuntu-Target, 26.04) | 192.168.56.40 (static) | 4 GB, 2 vCPU, 40 GB disk | Docker stack + Wazuh agent |
| Kali | 192.168.56.103 (DHCP) | 4 GB | Attacker |

Each VM has a host-only `vboxnet0` adapter (lab traffic) and a NAT adapter (internet for installs only).

## 1. Wazuh VM

Import the official appliance instead of installing by hand:
```bash
curl -fLO https://packages.wazuh.com/4.x/vm/wazuh-4.14.10.ova
VBoxManage import wazuh-4.14.10.ova --vsys 0 --vmname Wazuh
VBoxManage modifyvm Wazuh --nic1 hostonly --hostonlyadapter1 vboxnet0 --nic2 nat --graphicscontroller vmsvga
VBoxManage startvm Wazuh --type headless
```
Check: about a minute after boot, `https://192.168.56.104` shows the login page. Change the default passwords on first login.

## 2. Target VM: web stack

Target fixes needed on Ubuntu 26.04 + VirtualBox NAT:
- `echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4` (apt tried IPv6 with no IPv6 route)
- `/etc/netplan/60-nat.yaml`: NAT adapter `enp0s8` with `dhcp4: true`, `use-dns: false`, nameservers 1.1.1.1 / 8.8.8.8 (VirtualBox's DNS relay 10.0.3.3 is flaky)

The repo is private, so copy it from the host instead of cloning:
```bash
git archive HEAD | ssh soc-target@192.168.56.40 'mkdir -p /opt/cloud-sec-lab && tar -x -C /opt/cloud-sec-lab'
```
Then on the target:
```bash
cd /opt/cloud-sec-lab/infra
sudo mkdir -p logs/modsecurity && sudo chown 101:101 logs/modsecurity   # WAF runs as uid 101
sudo docker compose up -d
```
Check, from Kali:
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.56.40/                                      # 200
curl -s -o /dev/null -w '%{http_code}\n' 'http://192.168.56.40/?q=<script>alert(1)</script>'          # 403
curl -s -o /dev/null -w '%{http_code}\n' -G --data-urlencode "q=' OR 1=1--" http://192.168.56.40/rest/products/search   # 403
```
Then on the target: `tail -1 logs/modsecurity/audit.log` shows one JSON line per blocked request.

## 3. Target VM: Wazuh agent

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo WAZUH_MANAGER=192.168.56.104 apt install -y wazuh-agent=4.14.10-1
```
Paste the block from `detection/wazuh/agent-ossec-localfile.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then:
```bash
sudo systemctl enable --now wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log    # look for "Analyzing file: .../audit.log"
```
Check: the agent shows as Active in the dashboard (Agents).

## 4. Wazuh manager: custom rules

Copy `detection/wazuh/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`, then:
```bash
sudo /var/ossec/bin/wazuh-logtest          # paste one line of audit.log: expect rule 100101 or 100102
sudo systemctl restart wazuh-manager
```
Check: rerun the Kali attacks, then in the dashboard go to Threat Hunting and filter `rule.id: 10010*`.

## Known gotchas
- If the log folder isn't writable by uid 101, the WAF stays up but writes nothing.
- An unencoded space in a curl URL gives `000`; use `--data-urlencode`.
- `transaction.client_ip` is the real Kali IP only if Docker preserves the source IP (default iptables mode does). If you see 172.x.x.x, check `userland-proxy`.
