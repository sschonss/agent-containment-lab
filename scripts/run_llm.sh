#!/usr/bin/env bash
# One or more Ollama agent runs. Default: one insecure run and one contained run.
set -euo pipefail
cd "$(dirname "$0")/.."

model="${OLLAMA_MODEL:-qwen2.5:3b}"
runs="${LLM_RUNS:-1}"
mode="${LLM_MODE:-both}"
mkdir -p var/logs

if ! [[ "$runs" =~ ^[1-9][0-9]*$ ]]; then
  echo "LLM_RUNS must be a positive integer"
  exit 2
fi
if [[ "$mode" != "insecure" && "$mode" != "contained" && "$mode" != "both" ]]; then
  echo "LLM_MODE must be insecure, contained, or both"
  exit 2
fi

echo "===== ollama ====="
ollama_id="$(docker compose --profile llm ps -q ollama)"
if [[ -z "$ollama_id" ]]; then
  echo "ollama container is not running"
  exit 1
fi
ready=0
for _ in $(seq 1 40); do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$ollama_id" 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "ollama did not become healthy"
  exit 1
fi

if ! docker compose --profile llm exec -T ollama ollama show "$model" >/dev/null 2>&1; then
  echo "model ${model} is not in the local volume; pulling (needs network). For the talk, run make prepull first."
  docker compose --profile llm exec -T ollama ollama pull "$model"
fi

docker compose --profile llm exec -T ollama ollama show "$model" | sed -n '1,16p'

fail=0
run_one() {
  local which="$1"
  local n="$2"
  local before=0
  local after=0
  local log="var/logs/llm-${which}-${n}.log"
  if [[ -f var/attacker/received.jsonl ]]; then
    before="$(wc -l < var/attacker/received.jsonl | tr -d ' ')"
  fi
  echo "===== llm mode=${which} run=${n} ====="
  set +e
  docker compose run --rm --no-deps "$which" lab.llm_agent >"$log" 2>&1
  local code=$?
  set -e
  cat "$log"
  if [[ -f var/attacker/received.jsonl ]]; then
    after="$(wc -l < var/attacker/received.jsonl | tr -d ' ')"
  fi
  echo "llm.receipts mode=${which} run=${n} before=${before} after=${after} exit=${code}"
  if [[ "$code" -ne 0 ]]; then
    fail=1
  fi
}

if [[ "$mode" == "insecure" || "$mode" == "both" ]]; then
  for n in $(seq 1 "$runs"); do
    run_one insecure "$n"
  done
fi
if [[ "$mode" == "contained" || "$mode" == "both" ]]; then
  for n in $(seq 1 "$runs"); do
    run_one contained "$n"
  done
fi

echo "===== llm span marker scan ====="
python3 -m lab.check_spans --profile clean var/otel/traces.json
echo "===== llm done ====="
exit "$fail"
