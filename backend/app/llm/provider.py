"""LLM provider abstraction.

The LLM is used ONLY for structured reasoning summaries over facts that agents
obtained from registered tools. Facts never come from the model.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Protocol

import httpx

from app.config import Settings
from app.metrics import LLM_RETRIES, record_llm_latency

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    pass


class LLMResponse(dict):
    """Dict-shaped response: content, mode, latency_ms, model."""

    @property
    def content(self) -> str:
        return self["content"]

    @property
    def mode(self) -> str:
        return self["mode"]

    @property
    def latency_ms(self) -> float:
        return float(self.get("latency_ms", 0.0))

    @property
    def model(self) -> str:
        return str(self.get("model", ""))


class LLMProvider(Protocol):
    def generate(self, prompt: str, facts: Dict[str, Any]) -> LLMResponse:
        ...


def _fact_lines(facts: Dict[str, Any]) -> list[str]:
    lines = []
    for key in sorted(facts.keys()):
        value = facts[key]
        if isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True, default=str)
        else:
            text = str(value)
        if len(text) > 400:
            text = text[:400] + "..."
        lines.append(f"- {key}: {text}")
    return lines


class MockLLMProvider:
    """Deterministic provider. Returns reasoning derived STRICTLY from supplied
    facts; scenario-aware phrasing; always labels mode='mock'."""

    def generate(self, prompt: str, facts: Dict[str, Any]) -> LLMResponse:
        started = time.perf_counter()
        scenario = str(facts.get("scenario", "unspecified"))
        stage = str(facts.get("stage", "analysis"))
        conclusion = str(facts.get("conclusion", ""))
        lines = _fact_lines({k: v for k, v in facts.items() if k not in ("prompt",)})
        body = (
            f"[mock-reasoning | stage={stage} | scenario={scenario}] "
            f"{conclusion} "
            f"Basis (tool-derived facts only): {'; '.join(lines) if lines else 'no facts supplied'}"
        )
        latency_ms = (time.perf_counter() - started) * 1000.0
        record_llm_latency("mock", latency_ms / 1000.0)
        return LLMResponse(
            content=body,
            mode="mock",
            latency_ms=latency_ms,
            model="deterministic-mock",
        )


class OpenAICompatibleProvider:
    """Thin httpx client for any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, settings: Settings, timeout_s: float = 30.0, max_retries: int = 1):
        self._base_url = settings.llm_base_url.rstrip("/")
        self._api_key = settings.llm_api_key  # never logged
        self._model = settings.llm_model
        self._timeout = timeout_s
        self._max_retries = max_retries
        self.mode = settings.llm_mode

    def generate(self, prompt: str, facts: Dict[str, Any]) -> LLMResponse:
        fact_block = "\n".join(_fact_lines(facts))
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a recovery analysis assistant. Summarize ONLY from the "
                    "supplied facts. Do not invent data."
                ),
            },
            {"role": "user", "content": f"FACTS:\n{fact_block}\n\nTASK:\n{prompt}"},
        ]
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        attempt = 0
        last_err: Optional[Exception] = None
        while attempt <= self._max_retries:
            started = time.perf_counter()
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    resp = client.post(
                        f"{self._base_url}/chat/completions",
                        json={"model": self._model, "temperature": 0, "messages": messages},
                        headers=headers,
                    )
                latency_ms = (time.perf_counter() - started) * 1000.0
                resp.raise_for_status()
                payload = resp.json()
                content = payload["choices"][0]["message"]["content"]
                record_llm_latency(self.mode, latency_ms / 1000.0)
                return LLMResponse(
                    content=content, mode=self.mode, latency_ms=latency_ms, model=self._model
                )
            except Exception as exc:  # noqa: BLE001 - convert to ProviderError
                last_err = exc
                LLM_RETRIES.labels(mode=self.mode).inc()
                attempt += 1
        raise ProviderError(f"LLM call failed after retries: {last_err}")


def get_provider(settings: Settings) -> LLMProvider:
    if settings.is_mock_llm:
        return MockLLMProvider()
    logger.info("using openai-compatible llm at %s", settings.llm_base_url)
    return OpenAICompatibleProvider(settings)
