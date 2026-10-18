#!/usr/bin/env bash
# Builds the Go and statically-linked OpenSSL agent binaries used by tls_gate_demo.py.
set -euo pipefail
cd "$(dirname "$0")"
( cd go && CGO_ENABLED=0 go build -o ../go_agent main.go )
gcc -O1 -static -o static_agent static/agent.c -lssl -lcrypto -lpthread -ldl
echo "built: $(pwd)/go_agent $(pwd)/static_agent"
