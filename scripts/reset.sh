#!/usr/bin/env bash
# Removes this lab's containers, its named volumes (Tempo, Prometheus, Grafana),
# and the local var/ directory (exported spans and attacker receipts).
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down -v --remove-orphans
rm -rf var
echo "lab reset: containers, named volumes, and var/ removed"
