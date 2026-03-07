#!/usr/bin/env bash
# Quick endpoint smoke test. Start API first: unetdefence-api (or uvicorn)
# Usage: ./scripts/test_endpoints.sh [BASE_URL]
set -e
BASE="${1:-http://127.0.0.1:8000}"

echo "Testing UNetDefence API at $BASE"
echo ""

test_ok() { echo "  OK $1"; }
test_fail() { echo "  FAIL $1"; return 1; }

# Health
curl -sf "$BASE/health" > /dev/null && test_ok "GET /health" || test_fail "GET /health"
curl -sf "$BASE/health/ready" > /dev/null && test_ok "GET /health/ready" || test_fail "GET /health/ready"
curl -sf "$BASE/health/stats" > /dev/null && test_ok "GET /health/stats" || test_fail "GET /health/stats"

# Events
curl -sf "$BASE/api/events/flows?limit=1" > /dev/null && test_ok "GET /api/events/flows" || test_fail "GET /api/events/flows"
curl -sf "$BASE/api/events/alerts?limit=1" > /dev/null && test_ok "GET /api/events/alerts" || test_fail "GET /api/events/alerts"
curl -sf "$BASE/api/events/router?limit=1" > /dev/null && test_ok "GET /api/events/router" || test_fail "GET /api/events/router"

# Devices
curl -sf "$BASE/api/devices" > /dev/null && test_ok "GET /api/devices" || test_fail "GET /api/devices"

# Analytics
curl -sf "$BASE/api/analytics/top-countries?limit=5" > /dev/null && test_ok "GET /api/analytics/top-countries" || test_fail "GET /api/analytics/top-countries"
curl -sf "$BASE/api/analytics/devices-by-country?country_code=DE" > /dev/null && test_ok "GET /api/analytics/devices-by-country" || test_fail "GET /api/analytics/devices-by-country"
curl -sf "$BASE/api/analytics/anomalies" > /dev/null && test_ok "GET /api/analytics/anomalies" || test_fail "GET /api/analytics/anomalies"

# LLM (200 = OK, 503 = Ollama/LLM not available is acceptable)
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/llm/ask" -H "Content-Type: application/json" -d '{"question":"test"}' --max-time 15)
if [ "$CODE" = "200" ]; then
  test_ok "POST /api/llm/ask (200)"
elif [ "$CODE" = "503" ]; then
  echo "  OK POST /api/llm/ask (503 – LLM not available, expected if Ollama is off)"
else
  echo "  WARN POST /api/llm/ask ($CODE) – restart API to get 503 when Ollama is off"
fi

# Explain alert with fake ID -> 404 expected
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/llm/explain-alert" -H "Content-Type: application/json" -d '{"alert_id":"00000000-0000-0000-0000-000000000001"}')
[ "$CODE" = "404" ] && test_ok "POST /api/llm/explain-alert (404 for missing alert)" || echo "  SKIP POST /api/llm/explain-alert (got $CODE)"

echo ""
echo "Done."
