#!/usr/bin/env bash
set -euo pipefail

# Build images and start stack
compose_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$compose_dir"

echo "[+] Building and starting docker-compose stack"
docker compose up -d --build

# Wait for app to be healthy
printf "[+] Waiting for app health"
for i in {1..90}; do
  if docker compose ps --format json | jq -e '.[] | select(.Service=="app" and .Health=="healthy")' >/dev/null 2>&1; then
    echo ""; echo "[+] App is healthy"; break
  fi
  printf "."; sleep 2
  if [[ $i -eq 90 ]]; then echo ""; echo "[-] App failed to become healthy"; docker compose logs app; exit 1; fi
done

# Hit health endpoint
curl -fsS http://localhost:8080/api/v1/health | jq . || true

# Basic E2E smoke: 404 on non-existent contact should return 400/404 not 5xx
set +e
http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/contacts/00000000-0000-0000-0000-000000000000)
set -e
if [[ "$http_code" != "400" && "$http_code" != "404" ]]; then
  echo "[-] Unexpected status code from GET contact: $http_code"; docker compose logs app; exit 1
fi

echo "[+] E2E smoke succeeded"
