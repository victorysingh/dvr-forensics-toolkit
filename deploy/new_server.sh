#!/usr/bin/env bash
# Bring up a new hosted AnokhiDrishti server, run from a laptop with the repo
# (Linux, macOS, or Git Bash on Windows):
#
#     bash deploy/new_server.sh <user@ip> <commit> <secrets-folder>
#
# The machine must be a fresh Ubuntu 24.04 with 80 and 443 open to everyone
# and 22 open to you.  <secrets-folder> holds supabase.env, mail.env and
# field.key, the same three files the old server had (never commit them).
#
# 1. uploads `git archive <commit>` to /opt/anokhidrishti (skipped if code is
#    already there: later updates go through deploy/update_server.sh)
# 2. puts the three files in /etc/anokhidrishti, mode 600
# 3. runs deploy/setup_server.sh <ip-with-dashes>.sslip.io (SITE overrides)
# 4. turns on mail notices, encrypted addresses and real cases for the
#    accounts in REAL_CASES_FOR (default: demo), then restarts
#
# Accounts live in Supabase, so they carry over unchanged.  The SSH key comes
# from ANOKHI_KEY (default ~/.ssh/anokhidrishti-prod.pem).  Safe to run again.
set -euo pipefail

USAGE="usage: new_server.sh <user@ip> <commit> <secrets-folder>"
HOST="${1:?$USAGE}"
COMMIT="${2:?$USAGE}"
SECRETS="${3:?$USAGE}"
KEY="${ANOKHI_KEY:-$HOME/.ssh/anokhidrishti-prod.pem}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IP="${HOST#*@}"
SITE="${SITE:-${IP//./-}.sslip.io}"
REAL_CASES_FOR="${REAL_CASES_FOR:-demo}"
ETC=/etc/anokhidrishti
SSH=(ssh -i "$KEY" -o ConnectTimeout=10 -o ServerAliveInterval=30
     -o StrictHostKeyChecking=accept-new "$HOST")
SSH_TTY=(ssh -t -i "$KEY" -o ConnectTimeout=10 -o ServerAliveInterval=30 "$HOST")

for f in supabase.env mail.env field.key; do
    [ -f "$SECRETS/$f" ] || { echo "missing $SECRETS/$f" >&2; exit 1; }
done
SHA="$(git -C "$REPO" rev-parse --short "$COMMIT^{commit}")"

echo "[1/4] code"
if "${SSH[@]}" test -e /opt/anokhidrishti; then
    echo "  already there ($("${SSH[@]}" cat /opt/anokhidrishti/DEPLOYED_COMMIT 2>/dev/null || echo unknown));" \
         "use deploy/update_server.sh to change it"
else
    git -C "$REPO" archive "$SHA" | "${SSH[@]}" "set -e
        sudo rm -rf /opt/anokhidrishti.new
        sudo mkdir /opt/anokhidrishti.new
        sudo tar -x -C /opt/anokhidrishti.new
        echo '$SHA' | sudo tee /opt/anokhidrishti.new/DEPLOYED_COMMIT >/dev/null
        sudo mv /opt/anokhidrishti.new /opt/anokhidrishti"
    echo "  uploaded $SHA"
fi

echo "[2/4] supabase.env, mail.env, field.key -> $ETC"
# A different field key would leave every stored address unreadable.
THERE="$("${SSH[@]}" "sudo sha256sum $ETC/field.key 2>/dev/null | cut -d' ' -f1" || true)"
HERE="$(sha256sum "$SECRETS/field.key" | cut -d' ' -f1)"
if [ -n "$THERE" ] && [ "$THERE" != "$HERE" ]; then
    echo "  [!] the server already has a different field.key; not replacing it" >&2
    exit 1
fi
tar -C "$SECRETS" -cf - supabase.env mail.env field.key | "${SSH[@]}" "set -e
    sudo install -d -m 750 $ETC
    sudo tar -x --no-same-owner --no-same-permissions -C $ETC
    sudo chmod 600 $ETC/supabase.env $ETC/mail.env $ETC/field.key"

echo "[3/4] setup_server.sh $SITE"
"${SSH_TTY[@]}" "sudo bash /opt/anokhidrishti/deploy/setup_server.sh '$SITE'"

echo "[4/4] mail, encrypted addresses, real cases for: $REAL_CASES_FOR"
EXTRA="--mail --mail-env $ETC/mail.env --field-key $ETC/field.key"
[ -n "$REAL_CASES_FOR" ] && EXTRA="$EXTRA --real-cases-for $REAL_CASES_FOR"
"${SSH[@]}" "set -e
    sudo apt-get install -y -qq python3-cryptography >/dev/null
    sudo chown anokhi:anokhi $ETC/mail.env $ETC/field.key
    echo 'SERVE_EXTRA=$EXTRA' | sudo tee $ETC/serve.env >/dev/null
    sudo systemctl restart anokhidrishti
    sleep 4
    echo \"  service: \$(systemctl is-active anokhidrishti || true)\"
    sudo journalctl -u anokhidrishti -n 30 --no-pager -o cat \
        | grep -E 'mail notices|email addresses|real cases|rror' || true"

echo "done: https://$SITE/"
echo "next: point deploy/vercel/vercel.json at $SITE and redeploy the Vercel project"
