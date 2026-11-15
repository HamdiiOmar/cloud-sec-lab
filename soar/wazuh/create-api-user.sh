#!/usr/bin/env bash
# Phase 4: create a least-privilege Wazuh API user for Shuffle. Run it yourself on the host:
#   bash soar/wazuh/create-api-user.sh
# It asks for the Wazuh API *admin* login (never stored), then creates:
#   policy lab-active-response : active-response:command on agent:id:001 only
#   role   lab-soar            : that policy
#   user   shuffle             : that role, random password
# and writes WAZUH_API_USER / WAZUH_API_PASSWORD into soar/shuffle/.env (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE=shuffle/.env
[ -f "$ENV_FILE" ] || { echo "run soar/shuffle/setup.sh first"; exit 1; }

read -rp "Wazuh API admin user [wazuh]: " ADMIN; ADMIN=${ADMIN:-wazuh}
read -rsp "Wazuh API admin password: " ADMIN_PASS; echo

NEW_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)Aa1."   # policy: upper, lower, digit, symbol

ADMIN="$ADMIN" ADMIN_PASS="$ADMIN_PASS" NEW_PASS="$NEW_PASS" python3 - <<'EOF'
import base64, json, os, ssl, sys, urllib.request, urllib.error

API = "https://192.168.56.104:55000"
CTX = ssl._create_unverified_context()        # Wazuh API uses a self-signed certificate in the lab

def call(method, path, body=None, token=None, basic=None):
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = f"Bearer {token}"
    if basic: h["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    req = urllib.request.Request(API + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode()[:300]}")

try:
    token = call("POST", "/security/user/authenticate", basic=f'{os.environ["ADMIN"]}:{os.environ["ADMIN_PASS"]}')["data"]["token"]
except SystemExit as e:
    sys.exit(f"admin login failed ({e})")

def find(kind, name, field="name"):
    items = call("GET", f"/security/{kind}?limit=500", token=token)["data"]["affected_items"]
    return next((i for i in items if i.get(field) == name), None)

policy = find("policies", "lab-active-response") or call("POST", "/security/policies", {
    "name": "lab-active-response",
    "policy": {"actions": ["active-response:command"], "resources": ["agent:id:001"], "effect": "allow"},
}, token)["data"]["affected_items"][0]

role = find("roles", "lab-soar") or call("POST", "/security/roles", {"name": "lab-soar"}, token)["data"]["affected_items"][0]
if policy["id"] not in role.get("policies", []):
    call("POST", f'/security/roles/{role["id"]}/policies?policy_ids={policy["id"]}', token=token)

user = find("users", "shuffle", "username")
if user:   # reset the password so .env and Wazuh agree
    call("PUT", f'/security/users/{user["id"]}', {"password": os.environ["NEW_PASS"]}, token)
else:
    user = call("POST", "/security/users", {"username": "shuffle", "password": os.environ["NEW_PASS"]}, token)["data"]["affected_items"][0]
if role["id"] not in user.get("roles", []):
    call("POST", f'/security/users/{user["id"]}/roles?role_ids={role["id"]}', token=token)

# Prove the new user can log in
call("POST", "/security/user/authenticate", basic=f'shuffle:{os.environ["NEW_PASS"]}')
print("Wazuh API user 'shuffle' ready (role lab-soar: active-response on agent 001 only)")
EOF

sed -i '/^WAZUH_API_USER=/d;/^WAZUH_API_PASSWORD=/d' "$ENV_FILE"
printf 'WAZUH_API_USER=shuffle\nWAZUH_API_PASSWORD=%s\n' "$NEW_PASS" >> "$ENV_FILE"
echo "saved to soar/shuffle/.env"
