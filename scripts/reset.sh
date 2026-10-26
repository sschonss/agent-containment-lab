#!/usr/bin/env bash
# Removes this lab's containers and the telemetry volumes (Tempo, Prometheus, Grafana).
# The Ollama model volume stays, so `make prepull` is not required again for the model.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile demo --profile llm --profile manual down --remove-orphans
docker volume rm -f \
  agent-containment-lab_tempo-data \
  agent-containment-lab_prometheus-data \
  agent-containment-lab_grafana-data
rm -rf var
echo "lab reset: containers and telemetry volumes removed; ollama model volume kept; var/ removed"
