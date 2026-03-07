"""Configurable embedding adapter for semantic search."""

from abc import ABC, abstractmethod
from typing import List

from unetdefence.config import get_settings


class EmbeddingAdapter(ABC):
    """Abstract embedding provider: embed texts and return vectors."""

    @abstractmethod
    async def embed(self, texts: List[str]) -> List[List[float]]:
        """Return list of embedding vectors (each list of floats)."""
        pass

    @abstractmethod
    def dimensions(self) -> int:
        """Return vector dimension (e.g. 384, 1536)."""
        pass


class DisabledEmbeddingAdapter(EmbeddingAdapter):
    """No-op when embedding is disabled."""

    def __init__(self, dim: int = 384):
        self._dim = dim

    async def embed(self, texts: List[str]) -> List[List[float]]:
        return [[]] * len(texts)

    def dimensions(self) -> int:
        return self._dim


class OpenAIEmbeddingAdapter(EmbeddingAdapter):
    """OpenAI-compatible embedding API."""

    def __init__(self, base_url: str | None, api_key: str | None, model: str, dimensions: int):
        self._base_url = base_url or "https://api.openai.com/v1"
        self._api_key = api_key or ""
        self._model = model
        self._dim = dimensions

    async def embed(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{self._base_url.rstrip('/')}/embeddings",
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json={"input": texts, "model": self._model},
            )
            r.raise_for_status()
            data = r.json()
            return [item["embedding"] for item in data["data"]]

    def dimensions(self) -> int:
        return self._dim


class OllamaEmbeddingAdapter(EmbeddingAdapter):
    """Ollama local embedding API."""

    def __init__(self, base_url: str, model: str, dimensions: int):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dim = dimensions

    async def embed(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        import httpx
        out = []
        async with httpx.AsyncClient(timeout=60.0) as client:
            for t in texts:
                r = await client.post(
                    f"{self._base_url}/api/embeddings",
                    json={"model": self._model, "prompt": t},
                )
                r.raise_for_status()
                out.append(r.json().get("embedding", []))
        return out

    def dimensions(self) -> int:
        return self._dim


_adapter: EmbeddingAdapter | None = None


def get_embedding_adapter() -> EmbeddingAdapter:
    """Return configured embedding adapter (singleton)."""
    global _adapter
    if _adapter is not None:
        return _adapter
    s = get_settings().embedding
    if s.provider == "disabled":
        _adapter = DisabledEmbeddingAdapter(s.dimensions)
    elif s.provider == "openai":
        _adapter = OpenAIEmbeddingAdapter(s.base_url, s.api_key, s.model, s.dimensions)
    elif s.provider == "ollama":
        _adapter = OllamaEmbeddingAdapter(s.base_url or "http://localhost:11434", s.model, s.dimensions)
    else:
        _adapter = DisabledEmbeddingAdapter(s.dimensions)
    return _adapter
