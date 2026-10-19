#!/usr/bin/env bash
# Full reproduction. Run as root on Linux >= 6.x with cgroup v2, clang (bpf target), iptables.
# Every number in results/RESULTS.md comes from one run of this script (results/execution_log.txt).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
LOG="$ROOT/results/execution_log.txt"; mkdir -p results
export PYTHONPATH="$ROOT"
stage() { echo; echo "--- $1 ---"; date -u '+start: %H:%M:%S UTC'; }
{
echo "=== CONNECTION ESCROW: FULL REPRODUCTION RUN  $(date -u '+%Y-%m-%d %H:%M:%S UTC')  git: $(git rev-parse --short HEAD 2>/dev/null || echo n/a)"
echo "--- ENVIRONMENT ---"; uname -a; grep 'model name' /proc/cpuinfo | head -1; echo "vCPUs: $(nproc)"; grep MemTotal /proc/meminfo
python3 --version; clang --version | head -1; iptables --version; python3 -c "import cryptography; print('cryptography', cryptography.__version__)" 2>/dev/null || echo "cryptography: absent (pure-Python Ed25519)"
stage "STAGE 0: BUILD eBPF program"
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/escrow_connect4.bpf.c -o bpf/escrow_connect4.bpf.o && llvm-objdump -d bpf/escrow_connect4.bpf.o | grep -c "^ *[0-9a-f]*:" | sed 's/^/instructions: /'
echo "stage 0 exit: $?"
stage "STAGE 1: ADVERSARIAL SUITE, eBPF cgroup/connect4 hold point"
python3 tests/test_escrow.py bpf; echo "stage 1 exit: $?"
stage "STAGE 2: ADVERSARIAL SUITE, iptables REDIRECT hold point"
python3 tests/test_escrow.py iptables; echo "stage 2 exit: $?"
stage "STAGE 3: LATENCY, native Ed25519 (cryptography) if available"
python3 bench/bench.py 200; echo "stage 3 exit: $?"
stage "STAGE 4: LATENCY, pure-Python Ed25519"
ESCROW_PUREPY=1 python3 bench/bench.py 200; echo "stage 4 exit: $?"
stage "STAGE 5: CLI END-TO-END (curl as the agent)"
bash experiments/cli_smoke.sh; echo "stage 5 exit: $?"
stage "STAGE 6: CONTENT GATE (TLS plaintext via uprobe + ML, no termination) -- first-record vs stream gate; OpenSSL shared, Go crypto/tls, static OpenSSL"
bash experiments/agents/build.sh; echo "stage 6 build exit: $?"
python3 experiments/tls_gate_demo.py all both; echo "stage 6 exit: $?"
stage "STAGE 7: STREAM GATE ACCOUNTING (one write over several TLS records, then exfil)"
python3 experiments/tls_gate_multirecord.py; echo "stage 7 exit: $?"
echo; echo "RUN COMPLETE $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
} 2>&1 | tee "$LOG"
python3 experiments/gen_results_md.py
