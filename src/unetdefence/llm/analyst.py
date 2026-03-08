"""Configurable LLM analyst: answer questions, explain alerts, summarize."""

from abc import ABC, abstractmethod
from typing import Any

from unetdefence.config import get_settings


class LLMAnalyst(ABC):
    """Abstract LLM provider for analyst layer."""

    @abstractmethod
    async def generate_answer(self, question: str, context: str) -> tuple[str, str]:
        """Answer a natural-language question given retrieved context. Returns (answer, full_prompt)."""
        pass

    @abstractmethod
    async def explain_alert(self, alert_summary: str, related_context: str) -> str:
        """Explain why an alert might be suspicious."""
        pass

    @abstractmethod
    async def summarize_events(self, events_summary: str) -> str:
        """Produce a short summary of events."""
        pass


class DisabledLLMAnalyst(LLMAnalyst):
    """No-op when LLM is disabled."""

    async def generate_answer(self, question: str, context: str) -> tuple[str, str]:
        msg = "LLM is disabled. Enable a provider in configuration to get natural-language answers."
        full = f"[system: analyst with context]\n\nContext:\n{context}\n\nQuestion: {question}"
        return msg, full

    async def explain_alert(self, alert_summary: str, related_context: str) -> str:
        return "LLM is disabled. Enable a provider to get explanations."

    async def summarize_events(self, events_summary: str) -> str:
        return events_summary


class OpenAICompatibleAnalyst(LLMAnalyst):
    """OpenAI-compatible chat API (OpenAI, etc.)."""

    def __init__(self, base_url: str, api_key: str | None, model: str, timeout: float, max_tokens: int):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key or ""
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    async def _chat(self, system: str, user: str) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                f"{self._base_url.rstrip('/')}/v1/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": self._max_tokens,
                },
            )
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"].strip()

    async def generate_answer(self, question: str, context: str) -> tuple[str, str]:
        system = (
            "You are a network security analyst. Answer the user's question based only on the provided context. "
            "Cite data from the context. If the context does not contain enough information, say so."
        )
        user_content = f"Context:\n{context}\n\nQuestion: {question}"
        full_prompt = f"[System]\n{system}\n\n[User]\n{user_content}"
        answer = await self._chat(system, user_content)
        return answer, full_prompt

    async def explain_alert(self, alert_summary: str, related_context: str) -> str:
        return await self._chat(
            "You are a security analyst. Explain why this alert might be suspicious. Be concise.",
            f"Alert: {alert_summary}\n\nRelated context:\n{related_context}",
        )

    async def summarize_events(self, events_summary: str) -> str:
        return await self._chat(
            "Summarize the following security/network events in 2–4 sentences. Be factual and concise.",
            events_summary,
        )


class OllamaAnalyst(LLMAnalyst):
    """Ollama local API: uses /api/generate (primary), then /api/chat if 404."""

    def __init__(self, base_url: str, model: str, timeout: float, max_tokens: int):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    async def _chat(self, system: str, user: str) -> str:
        import httpx
        prompt = f"{system}\n\n{user}"
        payload_generate = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": self._max_tokens},
        }
        payload_chat = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"num_predict": self._max_tokens},
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for path in ("/api/generate", "/api/chat", "/generate"):
                r = await client.post(
                    f"{self._base_url}{path}",
                    json=payload_generate if "generate" in path else payload_chat,
                )
                if r.status_code == 200:
                    data = r.json()
                    if "response" in data:
                        return (data.get("response") or "").strip()
                    return (data.get("message", {}).get("content") or "").strip()
            r.raise_for_status()
            return ""

    async def generate_answer(self, question: str, context: str) -> tuple[str, str]:
        system = (
            "You are a network security analyst. Answer the user's question based only on the provided context. "
            "Cite data from the context. If the context does not contain enough information, say so."
        )
        user_content = f"Context:\n{context}\n\nQuestion: {question}"
        full_prompt = f"[System]\n{system}\n\n[User]\n{user_content}"
        answer = await self._chat(system, user_content)
        return answer, full_prompt

    async def explain_alert(self, alert_summary: str, related_context: str) -> str:
        system = (
            "You are a security analyst. Explain why this alert might be suspicious or noteworthy, "
            "using the related context. Be concise and factual."
        )
        return await self._chat(
            system,
            f"Alert: {alert_summary}\n\nRelated context:\n{related_context}",
        )

    async def summarize_events(self, events_summary: str) -> str:
        system = "Summarize the following security/network events in 2–4 sentences. Be factual and concise."
        return await self._chat(system, events_summary)


_analyst: LLMAnalyst | None = None


def get_llm_analyst() -> LLMAnalyst:
    """Return configured LLM analyst (singleton)."""
    global _analyst
    if _analyst is not None:
        return _analyst
    s = get_settings().llm
    if s.provider == "disabled":
        _analyst = DisabledLLMAnalyst()
    elif s.provider == "ollama":
        base = s.base_url or "http://localhost:11434"
        _analyst = OllamaAnalyst(base, s.model, s.timeout_seconds, s.max_tokens)
    elif s.provider == "openai":
        base = s.base_url or "https://api.openai.com"
        _analyst = OpenAICompatibleAnalyst(base, s.api_key, s.model, s.timeout_seconds, s.max_tokens)
    else:
        _analyst = DisabledLLMAnalyst()
    return _analyst
