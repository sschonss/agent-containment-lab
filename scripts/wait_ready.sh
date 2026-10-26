#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

wait_url() {
  local url="$1"
  local attempt
  for attempt in $(seq 1 40); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      echo "ready ${url}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${url}"
  return 1
}

wait_healthy() {
  local svc="$1"
  local attempt id status="missing"
  for attempt in $(seq 1 40); do
    id="$(docker compose ps -q "$svc" || true)"
    if [[ -n "$id" ]]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id")"
      if [[ "$status" == "healthy" ]]; then
        echo "healthy ${svc}"
        return 0
      fi
    fi
    sleep 1
  done
  echo "timeout waiting for ${svc} (last status: ${status})"
  docker compose logs --tail 50 "$svc" || true
  return 1
}

wait_url "http://127.0.0.1:13133/"
wait_url "http://127.0.0.1:9090/-/healthy"
wait_url "http://127.0.0.1:3200/ready"
wait_url "http://127.0.0.1:3001/api/health"
wait_healthy attacker
wait_healthy squid
