#!/usr/bin/env bash
# Quick check that Ollama is reachable and which endpoint works. Run on the same host as unetdefence-api.
set -e
BASE="${1:-http://localhost:11434}"
echo "Checking Ollama at $BASE"
echo ""
echo -n "  /api/version: "
curl -sf "$BASE/api/version" && echo "" || echo "FAIL"
echo -n "  POST /api/generate (stream=false): "
CODE=$(curl -s -o /tmp/ollama_gen.json -w "%{http_code}" -X POST "$BASE/api/generate" -H "Content-Type: application/json" -d '{"model":"llama3:8b","prompt":"Hi","stream":false}' --max-time 30)
echo "HTTP $CODE"
if [ "$CODE" = "200" ]; then
  echo "  -> OK (Ollama ready for LLM)"
else
  echo "  -> Response: $(head -c 200 /tmp/ollama_gen.json 2>/dev/null || echo 'none')"
fi
rm -f /tmp/ollama_gen.json
echo ""
echo "If both are OK, restart unetdefence-api and try: curl -X POST http://127.0.0.1:8000/api/llm/ask -H 'Content-Type: application/json' -d '{\"question\":\"Welche daten hast du?\"}'"
