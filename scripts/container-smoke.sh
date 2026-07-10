#!/usr/bin/env bash
set -euo pipefail

image="${1:-observability-agent-mcp:local}"
name="observability-agent-mcp-smoke-$$"
volume="observability-agent-mcp-smoke-runtime-$$"
temporary="$(mktemp -d)"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$temporary"
}
trap cleanup EXIT

cat >"$temporary/provider-config.yml" <<'YAML'
version: 1
providers:
  metrics: { type: prometheus-compatible, base_url: "http://127.0.0.1:1" }
  alerts: { type: vmalert, base_url: "http://127.0.0.1:1" }
  grafana: { type: grafana, base_url: "http://127.0.0.1:1" }
policy:
  named_queries:
    smoke-up: { expression: "up", label_keys: [] }
  service_health:
    smoke-service:
      query_template: smoke-up
      healthy_when: { operator: eq, value: 1 }
      summary: Smoke service availability
  dashboards:
    smoke-dashboard:
      uid: smoke-dashboard
      slug: smoke-dashboard
      title: Smoke Dashboard
      panels:
        smoke-panel: { id: 1 }
YAML
printf '%s\n' 'grafana-container-smoke-token' >"$temporary/grafana-token"
printf '%s\n' 'mcp-container-smoke-token-123' >"$temporary/mcp-token"
chmod 600 "$temporary"/*

docker volume create "$volume" >/dev/null
docker run --rm --user 0:0 \
  --volume "$temporary:/source:ro" \
  --volume "$volume:/target" \
  --entrypoint sh \
  "$image" -c 'cp /source/provider-config.yml /source/grafana-token /source/mcp-token /target/ && chmod 600 /target/* && chown 1000:1000 /target/*'

docker run -d --name "$name" \
  --publish 127.0.0.1::8765 \
  --env MCP_HTTP_HOST=0.0.0.0 \
  --env MCP_HTTP_PORT=8765 \
  --env MCP_HTTP_ALLOWED_HOSTS=127.0.0.1 \
  --env OBSERVABILITY_PROVIDER_CONFIG=/run/runtime/provider-config.yml \
  --env GRAFANA_TOKEN_FILE=/run/runtime/grafana-token \
  --env MCP_TOKEN_FILE=/run/runtime/mcp-token \
  --volume "$volume:/run/runtime:ro" \
  "$image" dist/http-cli.js >/dev/null

binding="$(docker port "$name" 8765/tcp | head -n 1)"
endpoint="http://$binding/mcp"
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 2 -o /dev/null "http://$binding/healthz" 2>/dev/null; then
    break
  fi
  if [[ "$attempt" == "30" ]]; then
    docker logs "$name" >&2
    exit 1
  fi
  sleep 1
done

test "$(docker inspect "$name" --format '{{.Config.User}}')" = "node"
node scripts/http-smoke.mjs "$endpoint" "$temporary/mcp-token"
echo "container_runtime_smoke=ok"
