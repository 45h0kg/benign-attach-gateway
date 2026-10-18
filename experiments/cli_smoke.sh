#!/usr/bin/env bash
# Starts verifier + interceptor from the CLI, puts this shell in a supervised cgroup, uses curl as the agent.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export PYTHONPATH="$ROOT"
D=$(mktemp -d); CG=/sys/fs/cgroup/unified/escrow-cli-$$; [ -d /sys/fs/cgroup/unified ] || CG=/sys/fs/cgroup/escrow-cli-$$
mkdir -p "$CG"
python3 -m escrow.cli keygen --out "$D/k" >/dev/null
cat > "$D/policy.json" <<EOP
{"workloads": {"spiffe://cluster.local/ns/demo/sa/agent": {"rules": [{"host": "127.0.0.1", "port": 18080, "action": "allow"}]}}, "default": "deny"}
EOP
echo "{\"$(echo $CG | sed 's#/sys/fs/cgroup/unified##; s#/sys/fs/cgroup##')\": {\"pod_uid\": \"cli-pod\", \"namespace\": \"demo\", \"name\": \"agent-0\", \"service_account\": \"agent\", \"spiffe_id\": \"spiffe://cluster.local/ns/demo/sa/agent\"}}" > "$D/pods.json"
python3 -m escrow.cli verifier --policy "$D/policy.json" --key "$D/k.secret" --record-keys-file "$D/k.record-key" --listen 127.0.0.1:18443 --audit "$D/v.jsonl" >"$D/v.log" 2>&1 & VP=$!
sleep 0.5
python3 -m escrow.cli interceptor --listen 127.0.0.1:15001 --verifier 127.0.0.1:18443 --verifier-pk-file "$D/k.public" --record-key-file "$D/k.record-key" --registry "$D/pods.json" --audit "$D/i.jsonl" --bpf-obj "$ROOT/bpf/escrow_connect4.bpf.o" --attach-cgroup "$CG" >"$D/i.log" 2>&1 & IP=$!
sleep 0.7
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'ok from 18080')
    def log_message(*a): pass
http.server.HTTPServer(('127.0.0.1',18080),H).serve_forever()" & UP=$!
sleep 0.3
echo $$ > "$CG/cgroup.procs"
echo "curl (supervised) -> 127.0.0.1:18080 : $(curl -s --max-time 3 http://127.0.0.1:18080/ || echo FAILED)"
curl -s --max-time 3 http://127.0.0.1:18443/v1/stats >/dev/null; echo "curl (supervised) -> verifier 18443 : exit=$? (56 = connection reset, expected)"
echo "curl (supervised) -> 127.0.0.1:18443 via explicit path again, now from a child shell: $(sh -c 'curl -s --max-time 3 http://127.0.0.1:18443/v1/stats || echo RESET')"
echo $$ > "$(dirname "$CG")/cgroup.procs"
kill $VP $IP $UP 2>/dev/null; wait 2>/dev/null; sleep 0.2
cat "$D/i.log"
python3 -c "
import json,sys
for l in open('$D/i.jsonl'):
    r=json.loads(l); print('receipt:', r['outcome'], r['reason'], r['dst'], 'comm=%s pid=%s cookie=%s'%(r['comm'], r['pid'], r['cookie']))"
rmdir "$CG"; rm -rf "$D"
