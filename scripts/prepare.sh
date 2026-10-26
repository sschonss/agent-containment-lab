#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p var/otel var/attacker var/none var/logs
chmod 777 var/otel var/attacker var/none var/logs
