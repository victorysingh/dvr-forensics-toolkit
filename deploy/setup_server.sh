#!/usr/bin/env bash
# One-shot setup of a hosted AnokhiDrishti server (Ubuntu 24.04), run as root
# from the uploaded code in /opt/anokhidrishti:
#
#     sudo bash /opt/anokhidrishti/deploy/setup_server.sh <site-name>
#
# <site-name> is the public name Caddy gets a certificate for, e.g.
# 13-200-1-2.sslip.io.  Before running it, put the Supabase credentials at
# /etc/anokhidrishti/supabase.env (see access/supabase.py); this script
# makes that file readable by the service user only.
#
# Safe to run again: every step checks before it changes anything.
set -euo pipefail

SITE="${1:?usage: setup_server.sh <site-name>}"
APP=/opt/anokhidrishti
DATA=/srv/anokhidrishti
STATE=/var/lib/anokhidrishti
ENV_FILE=/etc/anokhidrishti/supabase.env

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE - copy the Supabase credentials first" >&2; exit 1; }

echo "[1/6] packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 curl gnupg debian-keyring debian-archive-keyring apt-transport-https >/dev/null
if ! command -v caddy >/dev/null; then
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy >/dev/null
fi

echo "[2/6] service user and folders"
id anokhi >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin anokhi
install -d -o anokhi -g anokhi -m 750 "$DATA" "$DATA/out" "$DATA/images" "$STATE"
chown -R root:root "$APP"
chown root:anokhi "$(dirname "$ENV_FILE")"
chmod 750 "$(dirname "$ENV_FILE")"
chown anokhi:anokhi "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "[3/6] synthetic demo cases"
sudo -u anokhi env PS26150_SEAL_KEY="$STATE/ledger_seal.key" \
    python3 "$APP/deploy/make_demo_cases.py" --out "$DATA/out" --images "$DATA/images"

echo "[4/6] the console service"
install -m 644 "$APP/deploy/anokhidrishti.service" /etc/systemd/system/anokhidrishti.service
systemctl daemon-reload
systemctl enable --now anokhidrishti.service
systemctl restart anokhidrishti.service

echo "[5/6] HTTPS (Caddy) for $SITE"
install -m 644 "$APP/deploy/Caddyfile" /etc/caddy/Caddyfile
install -d /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironment=SITE=%s\n' "$SITE" > /etc/systemd/system/caddy.service.d/site.conf
systemctl daemon-reload
systemctl enable caddy >/dev/null
systemctl restart caddy

echo "[6/6] checks"
for i in $(seq 1 20); do
    curl -fsS -o /dev/null http://127.0.0.1:8150/access/login && break
    sleep 1
done
systemctl is-active anokhidrishti caddy
echo "done: https://$SITE/"
