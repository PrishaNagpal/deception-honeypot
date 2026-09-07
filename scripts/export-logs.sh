#!/usr/bin/env bash
# Copy container logs into ./data for Track B.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/data/cowrie/log" "$ROOT/data/dionaea/log" "$ROOT/data/dionaea/lib"
sudo docker cp hp-cowrie:/cowrie/cowrie-git/var/log/cowrie/. "$ROOT/data/cowrie/log/" || true
sudo docker cp hp-dionaea:/opt/dionaea/var/log/dionaea/. "$ROOT/data/dionaea/log/" || true
sudo docker cp hp-dionaea:/opt/dionaea/var/lib/. "$ROOT/data/dionaea/lib/" || true
echo "Logs copied under $ROOT/data"
