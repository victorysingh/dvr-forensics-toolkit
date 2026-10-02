#!/usr/bin/env bash
# Update a hosted AnokhiDrishti server to one commit, run from the laptop:
#
#     bash deploy/update_server.sh <user@host> <commit>
#
# 1. uploads `git archive <commit>` to /opt/anokhidrishti.new
# 2. runs the test suite there, printing each section as it goes (it takes
#    several minutes on a small instance)
# 3. only if it ends "0 failed": keeps the running copy as
#    /opt/anokhidrishti.prev, swaps the new one in and restarts the service
# 4. if the service does not come back and answer, swaps the old copy back
#    by itself
#
# Nothing under /srv (cases) or /etc (settings and keys) is touched.  The SSH
# key comes from ANOKHI_KEY (default ~/.ssh/anokhidrishti-prod.pem).
#
# To undo a good update later:
#     ssh <user@host> 'sudo mv /opt/anokhidrishti /opt/anokhidrishti.bad &&
#       sudo mv /opt/anokhidrishti.prev /opt/anokhidrishti &&
#       sudo systemctl restart anokhidrishti'
set -euo pipefail

HOST="${1:?usage: update_server.sh <user@host> <commit>}"
COMMIT="${2:?usage: update_server.sh <user@host> <commit>}"
KEY="${ANOKHI_KEY:-$HOME/.ssh/anokhidrishti-prod.pem}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH=(ssh -i "$KEY" -o ConnectTimeout=10 -o ServerAliveInterval=30 "$HOST")
# With a terminal, so that Ctrl-C during the tests stops them on the server too.
SSH_TTY=(ssh -t -i "$KEY" -o ConnectTimeout=10 -o ServerAliveInterval=30 "$HOST")

SHA="$(git -C "$REPO" rev-parse --short "$COMMIT^{commit}")"
echo "[1/4] uploading $SHA to $HOST:/opt/anokhidrishti.new"
git -C "$REPO" archive "$SHA" | "${SSH[@]}" "set -e
    sudo rm -rf /opt/anokhidrishti.new
    sudo mkdir /opt/anokhidrishti.new
    sudo tar -x -C /opt/anokhidrishti.new
    sudo chown -R root:root /opt/anokhidrishti.new
    echo '$SHA' | sudo tee /opt/anokhidrishti.new/DEPLOYED_COMMIT >/dev/null"

echo "[2/4] testing it on the server (sections print as they run; Ctrl-C is safe here)"
"${SSH_TTY[@]}" "rm -f /tmp/anokhidrishti-update-tests.log; cd /opt/anokhidrishti.new && sudo python3 -u tests/test_pipeline.py 2>&1 \
    | tee /tmp/anokhidrishti-update-tests.log \
    | grep --line-buffered -E '^\[|FAIL|passed, '" || true
RESULT="$("${SSH[@]}" "tail -n 1 /tmp/anokhidrishti-update-tests.log")"
if ! grep -qE ' passed, 0 failed' <<<"$RESULT"; then
    echo "  [!] tests did not pass ($RESULT); the live site is unchanged." >&2
    echo "      the full log is on the server at /tmp/anokhidrishti-update-tests.log" >&2
    exit 1
fi

echo "[3/4] swapping it in and restarting"
"${SSH[@]}" "set -e
    sudo rm -rf /opt/anokhidrishti.prev
    sudo mv /opt/anokhidrishti /opt/anokhidrishti.prev
    sudo mv /opt/anokhidrishti.new /opt/anokhidrishti
    sudo systemctl restart anokhidrishti"

echo "[4/4] checking it answers"
if "${SSH[@]}" "for i in \$(seq 1 15); do
        sleep 2
        code=\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8150/ || true)
        if systemctl is-active -q anokhidrishti && [ \"\$code\" != 000 ]; then
            echo \"  service active, answers HTTP \$code\"; exit 0
        fi
    done; exit 1"; then
    "${SSH[@]}" "sudo journalctl -u anokhidrishti -n 20 --no-pager | grep -iE 'mail|email|error' || true"
    echo "  [+] $SHA is live; the previous copy is at /opt/anokhidrishti.prev"
else
    echo "  [!] the service did not come back; putting the previous copy back" >&2
    "${SSH[@]}" "set -e
        sudo rm -rf /opt/anokhidrishti.bad
        sudo mv /opt/anokhidrishti /opt/anokhidrishti.bad
        sudo mv /opt/anokhidrishti.prev /opt/anokhidrishti
        sudo systemctl restart anokhidrishti
        sudo journalctl -u anokhidrishti -n 30 --no-pager"
    exit 1
fi
