"""
Ensure required Ollama models are available. Uses only the Ollama HTTP API (no CLI).

Reads UNETDEFENCE_LLM_* and UNETDEFENCE_EMBEDDING_* config; when provider is 'ollama',
checks if the configured model is present and pulls it via POST /api/pull if missing.

Usage:
  python -m unetdefence.scripts.ensure_ollama_models
  # or: unetdefence-ensure-ollama (if entry point is added)
"""

import asyncio
import json
import sys
from pathlib import Path

import httpx

# Load .env from project root so UNETDEFENCE_* overrides (e.g. LLM_MODEL) are applied
# when running as installed script (cwd may not be project root)
try:
    from dotenv import load_dotenv
    _project_root = Path(__file__).resolve().parent.parent.parent.parent
    load_dotenv(_project_root / ".env")
except Exception:
    pass

from unetdefence.config import get_settings


def get_required_ollama_models() -> list[tuple[str, str]]:
    """Return list of (base_url, model_name) for each Ollama model required by config."""
    settings = get_settings()
    out: list[tuple[str, str]] = []
    base = "http://localhost:11434"
    if settings.llm.provider == "ollama":
        base = (settings.llm.base_url or "http://localhost:11434").rstrip("/")
        out.append((base, settings.llm.model))
    if settings.embedding.provider == "ollama":
        base_emb = (settings.embedding.base_url or "http://localhost:11434").rstrip("/")
        out.append((base_emb, settings.embedding.model))
    return out


def normalize_base_url(base: str) -> str:
    return base.rstrip("/")


async def list_models(base_url: str, client: httpx.AsyncClient) -> list[str]:
    """GET /api/tags; return list of model names (e.g. 'llama3.2:latest')."""
    try:
        r = await client.get(f"{normalize_base_url(base_url)}/api/tags", timeout=30.0)
        r.raise_for_status()
        data = r.json()
        models = data.get("models") or []
        return [m.get("name") or m.get("model") or "" for m in models if m.get("name") or m.get("model")]
    except httpx.HTTPError as e:
        print(f"Failed to list models from {base_url}: {e}", file=sys.stderr)
        return []


def model_matches(have: str, want: str) -> bool:
    """True if local model name satisfies required name (exact or tag match)."""
    if not have or not want:
        return False
    # Exact match
    if have == want:
        return True
    # want is base name e.g. "llama3.2", have is "llama3.2:latest"
    if have.startswith(want + ":") or have.startswith(want + " "):
        return True
    # want includes tag e.g. "llama3.2:3b", have might be "llama3.2:3b-instruct-q4_K_M"
    if have.startswith(want):
        return True
    return False


async def pull_model(base_url: str, model_name: str, client: httpx.AsyncClient) -> bool:
    """POST /api/pull for the given model. Returns True on success."""
    url = f"{normalize_base_url(base_url)}/api/pull"
    try:
        async with client.stream(
            "POST",
            url,
            json={"model": model_name},
            timeout=600.0,
        ) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if "status" in msg:
                        print(f"  {msg['status']}")
                    if "completed" in msg and "total" in msg:
                        c, t = msg["completed"], msg["total"]
                        if t and t > 0:
                            pct = 100 * c / t
                            print(f"  {pct:.0f}% ({c}/{t})")
                except json.JSONDecodeError:
                    pass
        return True
    except httpx.HTTPError as e:
        print(f"Pull failed for {model_name}: {e}", file=sys.stderr)
        return False


async def run() -> int:
    required = get_required_ollama_models()
    if not required:
        print("No Ollama models required by config (set UNETDEFENCE_LLM_PROVIDER=ollama and/or UNETDEFENCE_EMBEDDING_PROVIDER=ollama).")
        return 0

    # Deduplicate by (base_url, model_name)
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for base, model in required:
        key = (normalize_base_url(base), model)
        if key not in seen:
            seen.add(key)
            unique.append((base, model))

    async with httpx.AsyncClient() as client:
        for base_url, model_name in unique:
            print(f"Checking Ollama at {base_url} for model '{model_name}'...")
            existing = await list_models(base_url, client)
            if any(model_matches(h, model_name) for h in existing):
                print(f"  Model '{model_name}' already present.")
                continue
            print(f"  Pulling '{model_name}'...")
            ok = await pull_model(base_url, model_name, client)
            if not ok:
                return 1
            print(f"  Done: {model_name}")

    print("All required Ollama models are available.")
    return 0


def main() -> None:
    exit_code = asyncio.run(run())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
