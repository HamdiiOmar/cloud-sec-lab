# Phase 4: SOAR (automatic block and notify)

Deliverable: an attack from Kali gets Kali blocked at the target's firewall within a minute, and a Discord message says who was blocked and why.

## Flow

```
Kali attack ─► WAF / Suricata / sshd ─► Wazuh agent ─► Wazuh manager (correlation rule)
                                                            │ integration "shuffle"
                                                            ▼
                     Shuffle playbook: parse_alert ─► wazuh_login ─► block_ip ─► notify_discord
                                                                        │ Wazuh API PUT /active-response
                                                                        ▼
                     Target: Wazuh agent ─► lab-block.sh ─► nftables set lab_block/blocklist (10 min)
```

| Piece | Where | File |
|---|---|---|
| Block-list | target, nftables `inet lab_block`, hook prerouting priority -350 | `soar/target/lab-block.nft` |
| Block script (validates IP, refuses lab infrastructure) | target, `/usr/local/sbin/lab-block` | `soar/target/lab-block.sh` |
| Active Response wrapper | target, `/var/ossec/active-response/bin/lab-block.sh` | `soar/target/lab-block-ar.sh` |
| Install (block-list, systemd unit, `soar` user) | target | `soar/target/install.sh` |
| Wazuh → Shuffle integration | manager `ossec.conf` | `detection/wazuh/manager-ossec-soar.xml` |
| Least-privilege API user `shuffle` | Wazuh API | `soar/wazuh/create-api-user.sh` |
| Shuffle 2.3.0 | host (UI http://localhost:3001) | `soar/shuffle/docker-compose.yml`, `setup.sh` |
| Playbook (generated through Shuffle's API) | Shuffle | `soar/shuffle/build_workflow.py` |

Only the correlation rules trigger the playbook: 100103 (automated web attack), 100105 (login brute force), 100111 (port scan), 5763 (SSH brute force). Forwarding every SQLi alert would start ~170 runs per sqlmap scan.

## Design decisions

- **Block before Docker.** The WAF's port is DNATed by Docker before the normal `input` chain, so a classic INPUT drop would miss it. The `lab_block` table hooks `prerouting` at priority -350, ahead of Docker's raw (-300) and nat (-100) chains. It lives in its own table and is loaded by `lab-block.service`, not `nftables.service`, whose default config starts with `flush ruleset` and would wipe Docker's rules.
- **Blocks expire on their own.** nftables set timeout (10 min), so the playbook is stateless.
- **Protected IPs.** The script and the playbook both refuse to block the host (Shuffle, Prometheus), the Wazuh VM and the target.
- **Least privilege.** The Wazuh API user `shuffle` has one policy: `active-response:command` on `agent:id:001`. Secrets (Shuffle API key, Wazuh API password, Discord webhook) live in `soar/shuffle/.env`, which is gitignored.
- **`!lab-block.sh`, not a named command.** A named Active Response command is only accepted by the API when it also has an `<active-response>` block, which would make Wazuh block on its own and bypass Shuffle. The script-name form runs the script directly.
- **No SSH app.** Shuffle's SSH app is no longer in its app repository; the playbook uses the built-in HTTP app against the Wazuh API instead.

## Problems found and fixed

| Problem | Fix |
|---|---|
| Upstream compose: images on `:latest`, OpenSearch password is a public default, backend and OpenSearch published on all interfaces | Pinned 2.3.0, random secrets from `setup.sh`, UI on localhost, backend on localhost + lab IP only, OpenSearch not published |
| Orborus tried to turn the host's Docker into a Swarm manager (`SHUFFLE_SWARM_CONFIG=run`) and hung | Removed it; Orborus now starts one worker container per run |
| Target clock 3.7 days behind after a VirtualBox pause; chrony only steps in its first 3 updates | `makestep 1 -1` in `/etc/chrony/chrony.conf` |
| **False positive:** an open Juice Shop tab in Kali polled `/socket.io/` and was blocked 159 times (CRS 920350 + 920420), firing 100103 and getting Kali blocked for browsing | `infra/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`: drop 920350 (lab uses IPs), drop 920420 for `/socket.io/` only |

## Test (from Kali)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.56.40/    # 200
nikto -h http://192.168.56.40 -maxtime 60s                          # starts timing out
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.56.40/    # 000: blocked
```
Discord shows "Blocked 192.168.56.103 for 10 minutes". Access returns after 10 minutes, or unblock early on the target:
```bash
sudo /usr/local/sbin/lab-block unblock 192.168.56.103
```

## Known limitation

One nikto run fired 100103 four times, so Kali was "blocked" four times and Discord got four messages. A correlation rule keeps firing while the attack continues. Possible fixes: `ignore` on the Wazuh rules, or have the playbook skip IPs that are already in the block-list.
