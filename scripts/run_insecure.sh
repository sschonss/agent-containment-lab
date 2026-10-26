#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p var/logs
before=0
if [[ -f var/attacker/received.jsonl ]]; then
  before="$(wc -l < var/attacker/received.jsonl | tr -d ' ')"
fi

set +e
docker compose run --rm --no-deps insecure lab.agent >var/logs/insecure-agent.log 2>&1
code=$?
set -e
cat var/logs/insecure-agent.log
if [[ "$code" -ne 0 ]]; then
  echo "insecure agent exited ${code}"
  exit "$code"
fi

echo "===== attacker receipts ====="
if [[ ! -f var/attacker/received.jsonl ]]; then
  echo "attacker received nothing"
  exit 1
fi
after="$(wc -l < var/attacker/received.jsonl | tr -d ' ')"
echo "receipts_before=${before} receipts_after=${after}"
if [[ "$after" -le "$before" ]]; then
  echo "attacker did not receive a new body"
  exit 1
fi
python3 - <<'PY'
from pathlib import Path
text = Path("var/attacker/received.jsonl").read_text(encoding="utf-8")
markers = [line.strip() for line in Path("fixtures/secret-markers.txt").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
missing = [marker for marker in markers if marker not in text]
if missing:
    raise SystemExit("attacker log is missing a planted secret marker")
print(f"attacker log contains {len(markers)} planted secret markers")
PY

python3 - <<'PY'
import subprocess
import sys
import time
path = "var/otel/traces.json"
for _ in range(20):
    completed = subprocess.run([sys.executable, "-m", "lab.check_spans", "--profile", "insecure", path])
    if completed.returncode == 0:
        raise SystemExit(0)
    if completed.returncode == 1:
        raise SystemExit("span export contains a secret or the planted prompt")
    time.sleep(1)
raise SystemExit("span export was not ready for the insecure profile")
PY
echo "===== insecure done ====="
