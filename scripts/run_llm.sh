#!/usr/bin/env bash
# Optional hook for a real local agent. The default demo does not call this.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${AGENT_COMMAND:-}" ]]; then
  echo "AGENT_COMMAND is empty. The default demo is the scripted agent in lab/agent.py."
  echo "Set AGENT_COMMAND to a shell command if you want to run your own binary inside the contained network."
  exit 2
fi
docker compose run --rm --no-deps --entrypoint sh contained -lc "$AGENT_COMMAND"
