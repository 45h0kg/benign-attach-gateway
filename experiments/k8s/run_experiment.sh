#!/usr/bin/env bash
# On-cluster experiment driver. Assumes a running cluster, `escrow/lab:dev` imported,
# and the lab namespace (lab.yaml) up. kubectl is passed in as $KUBECTL.
#   KUBECTL="k3s kubectl" bash experiments/k8s/run_experiment.sh
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
K="${KUBECTL:-kubectl}"
OUT="$ROOT/results/k8s"; mkdir -p "$OUT"
export PYTHONPATH="$ROOT"

echo "=== Generate keys and policy ==="
D="$OUT/keys"; mkdir -p "$D"
python3 -m escrow.cli keygen --out "$D/v" >/dev/null
INTERNAL_IP=$($K -n lab get svc internal-api -o jsonpath='{.spec.clusterIP}')
EXTERNAL_IP=$($K -n lab get svc external-sink -o jsonpath='{.spec.clusterIP}')
echo "internal-api $INTERNAL_IP   external-sink $EXTERNAL_IP"
cat > "$OUT/policy.json" <<EOP
{"workloads": {
   "spiffe://cluster.local/ns/lab/sa/agent": {
     "rules": [
       {"svc": "lab/internal-api", "methods": ["GET"], "action": "allow"},
       {"svc": "lab/internal-api", "methods": ["POST"], "path_prefix": "/collect", "action": "allow"}
     ],
     "budget_per_minute": 240}},
 "default": "deny"}
EOP

echo "=== Deploy verifier and node agent (keys/policy/code via configmaps+secrets) ==="
$K create namespace escrow-system --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n escrow-system create secret generic escrow-verifier-key \
  --from-file=verifier.secret="$D/v.secret" --from-file=record-key="$D/v.record-key" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n escrow-system create secret generic escrow-node-keys \
  --from-file=verifier.public="$D/v.public" --from-file=record-key="$D/v.record-key" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n escrow-system create configmap escrow-policy --from-file=policy.json="$OUT/policy.json" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n escrow-system create configmap escrow-code --from-file="$ROOT/escrow" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
$K apply -f "$ROOT/experiments/k8s/node.yaml" >/dev/null

echo "=== Wait for verifier and node agent ==="
$K -n escrow-system rollout status deploy/escrow-verifier --timeout=120s
$K -n escrow-system rollout status ds/escrow-node-agent --timeout=120s
sleep 5
$K -n escrow-system get pods -o wide

echo "=== Baseline: agent with NO supervision (label absent) ==="
TASK_JSON=$(cat <<EOT
{"steps":[
  {"method":"GET","url":"http://internal-api.lab.svc.cluster.local/data"},
  {"method":"POST","url":"http://internal-api.lab.svc.cluster.local/collect","body":"step-report"},
  {"method":"POST","url":"http://external-sink.lab.svc.cluster.local/upload","body":"data-going-outside"},
  {"method":"GET","url":"http://external-sink.lab.svc.cluster.local/data"}
],"child_url":"http://external-sink.lab.svc.cluster.local/upload"}
EOT
)
run_agent () {   # name label
  $K -n lab delete pod "$1" --ignore-not-found --wait=true >/dev/null 2>&1
  $K -n lab run "$1" --image=escrow/lab:dev --image-pull-policy=Never --restart=Never \
     --labels="app=agent${2:+,$2}" --overrides="{\"spec\":{\"serviceAccountName\":\"agent\",\"containers\":[{\"name\":\"$1\",\"image\":\"escrow/lab:dev\",\"imagePullPolicy\":\"Never\",\"command\":[\"python3\",\"/opt/escrow/lab/agent.py\"],\"env\":[{\"name\":\"AGENT_NAME\",\"value\":\"$1\"},{\"name\":\"TASK\",\"value\":$(python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))' <<<"$TASK_JSON")}]}]}}" >/dev/null
  $K -n lab wait --for=jsonpath='{.status.phase}'=Succeeded pod/"$1" --timeout=60s >/dev/null 2>&1
  $K -n lab logs "$1" 2>/dev/null
}
$K -n lab create serviceaccount agent --dry-run=client -o yaml | $K apply -f - >/dev/null

echo "--- unsupervised agent (no escrow label):"
run_agent agent-free "" | tee "$OUT/agent_unsupervised.jsonl"

echo "=== Supervised: agent with escrow.io/supervised=true ==="
echo "--- supervised agent (escrow enforces per-connection):"
run_agent agent-supervised "escrow.io/supervised=true" | tee "$OUT/agent_supervised.jsonl"

echo "=== What each destination actually received ==="
$K -n lab exec deploy/internal-api -- python3 -c "import urllib.request,json;print('internal-api:',urllib.request.urlopen('http://127.0.0.1:8080/log').read().decode())" 2>/dev/null | tee "$OUT/internal_received.txt"
$K -n lab exec deploy/external-sink -- python3 -c "import urllib.request,json;print('external-sink:',urllib.request.urlopen('http://127.0.0.1:8080/log').read().decode())" 2>/dev/null | tee "$OUT/external_received.txt"

echo "=== Interceptor receipts (from the node agent) ==="
$K -n escrow-system exec ds/escrow-node-agent -- sh -c 'cat /var/lib/escrow/interceptor_audit.jsonl 2>/dev/null | tail -20' | tee "$OUT/receipts.jsonl"
echo "=== kernel counters ==="
$K -n escrow-system logs ds/escrow-node-agent 2>/dev/null | grep -E "attached|hold point|registry" | tail -8

echo; echo "Artifacts in $OUT"
