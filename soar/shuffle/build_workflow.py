#!/usr/bin/env python3
"""Phase 4: create or update the Shuffle playbook through Shuffle's API.

Webhook (Wazuh alert) -> parse_alert -> wazuh_login -> block_ip (Wazuh Active Response) -> notify_discord

Secrets are read from soar/shuffle/.env (gitignored), never written to the repo:
  SHUFFLE_DEFAULT_APIKEY        Shuffle API key (created by setup.sh)
  WAZUH_API_USER / WAZUH_API_PASSWORD   limited Wazuh API user that may only run active responses
  DISCORD_WEBHOOK_URL           channel webhook for notifications
Usage: python3 build_workflow.py
"""
import json
import pathlib
import urllib.request
import uuid

HERE = pathlib.Path(__file__).parent
SHUFFLE = "http://127.0.0.1:5001"
WAZUH_API = "https://192.168.56.104:55000"
TARGET_AGENT = "001"            # Wazuh agent ID of Ubuntu-Target
BAN_MINUTES = "10"
WORKFLOW_NAME = "Wazuh alert - block and notify"


def load_env():
    env = {}
    for line in (HERE / ".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.split(" #")[0].strip().strip('"')
    return env


ENV = load_env()


def api(method, path, body=None):
    req = urllib.request.Request(
        SHUFFLE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {ENV['SHUFFLE_DEFAULT_APIKEY']}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"{}")


APPS = {a["name"]: a for a in api("GET", "/api/v1/apps")}


def action(label, app_name, action_name, x, values):
    """Build an action from the app's own definition so every parameter has the shape Shuffle expects."""
    app = APPS[app_name]
    spec = next(a for a in app["actions"] if a["name"] == action_name)
    params = []
    for p in spec["parameters"]:
        p = dict(p)
        if p["name"] in values:
            p["value"] = values[p["name"]]
        params.append(p)
    return {
        "app_name": app["name"], "app_version": app["app_version"], "app_id": app["id"],
        "id": str(uuid.uuid4()), "name": action_name, "label": label,
        "parameters": params, "environment": "Shuffle", "is_valid": True, "sharing": False,
        "position": {"x": x, "y": 300}, "isStartNode": False, "errors": [],
    }


# Runs inside Shuffle Tools. $exec is replaced by Shuffle with the webhook body (the Wazuh alert).
# The Wazuh "shuffle" integration wraps the alert in {"all_fields": {...}}.
PARSE_CODE = r'''
import json, ipaddress

raw = r"""$exec"""
body = json.loads(raw)
alert = body.get("all_fields", body)
data = alert.get("data", {})
rule = alert.get("rule", {})

ip = data.get("srcip") or data.get("src_ip") or data.get("transaction", {}).get("client_ip")
PROTECTED = {"192.168.56.1", "192.168.56.104", "192.168.56.40", "127.0.0.1"}

if not ip:
    raise Exception("no source IP in alert " + str(rule.get("id")))
ipaddress.ip_address(ip)                      # raises on garbage
if ip in PROTECTED:
    raise Exception("refusing to block protected lab IP " + ip)

print(json.dumps({
    "ip": ip,
    "rule_id": rule.get("id"),
    "level": rule.get("level"),
    "description": rule.get("description"),
    "agent": alert.get("agent", {}).get("name"),
    "mitre": ", ".join(rule.get("mitre", {}).get("technique", [])),
}))
'''


def build():
    existing = [w for w in api("GET", "/api/v1/workflows") if w["name"] == WORKFLOW_NAME]
    wf = existing[0] if existing else api("POST", "/api/v1/workflows", {"name": WORKFLOW_NAME})
    wf_id = wf["id"]

    parse = action("parse_alert", "Shuffle Tools", "execute_python", 300, {"code": PARSE_CODE})
    login = action("wazuh_login", "http", "POST", 550, {
        "url": f"{WAZUH_API}/security/user/authenticate?raw=true",
        "username": ENV.get("WAZUH_API_USER", "CHANGE_ME"),
        "password": ENV.get("WAZUH_API_PASSWORD", "CHANGE_ME"),
        "verify": "false",
    })
    block = action("block_ip", "http", "PUT", 800, {
        "url": f"{WAZUH_API}/active-response?agents_list={TARGET_AGENT}",
        "headers": "Content-Type: application/json\nAuthorization: Bearer $wazuh_login.body",
        "body": json.dumps({"command": "!lab-block.sh",
                            "arguments": ["$parse_alert.message.ip", BAN_MINUTES]}),
        "verify": "false",
    })
    notify = action("notify_discord", "http", "POST", 1050, {
        "url": ENV.get("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/CHANGE_ME"),
        "headers": "Content-Type: application/json",
        "body": json.dumps({"username": "Lab SOAR", "embeds": [{
            "title": "Blocked $parse_alert.message.ip for " + BAN_MINUTES + " minutes",
            "description": "$parse_alert.message.description",
            "color": 15158332,
            "fields": [
                {"name": "Rule", "value": "$parse_alert.message.rule_id (level $parse_alert.message.level)", "inline": True},
                {"name": "Agent", "value": "$parse_alert.message.agent", "inline": True},
                {"name": "MITRE", "value": "$parse_alert.message.mitre"},
                {"name": "Wazuh response", "value": "$block_ip.status"},
            ]}]}),
    })
    parse["isStartNode"] = True
    actions = [parse, login, block, notify]

    # Keep the existing webhook on re-runs: Wazuh's ossec.conf points at its URL
    old_hooks = [t for t in (wf.get("triggers") or []) if t.get("trigger_type") == "WEBHOOK"]
    trigger_id = old_hooks[0]["id"] if old_hooks else str(uuid.uuid4())
    hook_url = f"http://192.168.56.1:5001/api/v1/hooks/webhook_{trigger_id}"
    trigger = {
        "app_name": "Webhook", "app_version": "1.0.0", "id": trigger_id, "label": "wazuh_alerts",
        "name": "Webhook", "trigger_type": "WEBHOOK", "status": "uninitialized", "environment": "Shuffle",
        "description": "Wazuh high-severity alerts", "is_valid": True, "position": {"x": 50, "y": 300},
        "parameters": [{"name": "url", "value": hook_url}, {"name": "tmp", "value": ""},
                       {"name": "auth_headers", "value": ""}, {"name": "custom_response_body", "value": ""},
                       {"name": "await_response", "value": "v1"}],
    }

    chain = [trigger] + actions
    branches = [{"id": str(uuid.uuid4()), "source_id": a["id"], "destination_id": b["id"], "conditions": []}
                for a, b in zip(chain, chain[1:])]

    wf.update({"name": WORKFLOW_NAME, "actions": actions, "triggers": [trigger], "branches": branches,
               "start": parse["id"], "description": __doc__.strip().splitlines()[0]})
    api("PUT", f"/api/v1/workflows/{wf_id}", wf)

    # (Re)register the webhook so it points at the current start node
    api("POST", f"/api/v1/hooks/new", {
        "name": "wazuh_alerts", "type": "webhook", "id": trigger_id, "workflow": wf_id,
        "start": parse["id"], "environment": "Shuffle", "auth": "", "custom_response": "", "version": "v1",
    })
    print(json.dumps({"workflow_id": wf_id, "webhook_url": hook_url}))


if __name__ == "__main__":
    build()
