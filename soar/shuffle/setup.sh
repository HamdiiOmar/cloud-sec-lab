#!/usr/bin/env bash
# Phase 4: first-time setup of Shuffle on the host. Re-running keeps the existing .env and data.
set -euo pipefail
cd "$(dirname "$0")"

rand() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

if [ ! -f .env ]; then
	curl -fsSL https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/.env -o .env
	# Replace upstream's publicly known defaults with random secrets
	OS_PASS="$(rand)Aa1!"                       # OpenSearch requires upper, lower, digit, special
	sed -i \
		-e "s|^SHUFFLE_OPENSEARCH_PASSWORD=.*|SHUFFLE_OPENSEARCH_PASSWORD=\"$OS_PASS\"|" \
		-e "s|^OPENSEARCH_INITIAL_ADMIN_PASSWORD=.*|OPENSEARCH_INITIAL_ADMIN_PASSWORD=\"$OS_PASS\"|" \
		-e "s|^SHUFFLE_DEFAULT_USERNAME=.*|SHUFFLE_DEFAULT_USERNAME=admin|" \
		-e "s|^SHUFFLE_DEFAULT_PASSWORD=.*|SHUFFLE_DEFAULT_PASSWORD=$(rand)|" \
		-e "s|^SHUFFLE_DEFAULT_APIKEY=.*|SHUFFLE_DEFAULT_APIKEY=$(uuidgen)|" \
		-e "s|^SHUFFLE_ENCRYPTION_MODIFIER=.*|SHUFFLE_ENCRYPTION_MODIFIER=$(rand)|" \
		-e "s|^TZ=.*|TZ=UTC|" \
		.env
	chmod 600 .env
	echo "created .env (admin login and API key inside)"
fi

mkdir -p shuffle-apps shuffle-files shuffle-database
docker compose up -d
