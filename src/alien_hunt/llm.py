"""OpenAI-compatible chat and embeddings. The key is never part of repr or logs."""

from __future__ import annotations

import json
import logging

from alien_hunt.config import Config
from alien_hunt.redact import install_secret_filter, redact
from alien_hunt.types import ChatResponse, EmbedResponse, ToolCall

log = logging.getLogger("alien_hunt")


class LLMError(Exception):
    """The model endpoint failed. The message has already been redacted."""


def estimate_tokens(text: str) -> int:
    """Rough token count when the endpoint omits usage."""

    return max(1, len(text) // 4)


class OpenAIModel:
    """Chat and embeddings against one configured base URL."""

    def __init__(self, config: Config) -> None:
        self.model = config.model
        self.embedding_model = config.embedding_model
        self.base_url = config.base_url
        secret = config.api_key()
        install_secret_filter(secret)
        self._secret = secret
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("the openai package is not installed") from exc
        try:
            self._client = OpenAI(base_url=config.base_url, api_key=secret)
        except Exception as exc:
            raise LLMError(str(redact(str(exc), secret))) from None

    def __repr__(self) -> str:
        return f"OpenAIModel(model={self.model!r}, base_url={self.base_url!r})"

    def chat(self, *, messages: list, tools: list | None, max_tokens: int) -> ChatResponse:
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        if tools:
            kwargs["tools"] = tools
        try:
            response = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise LLMError(str(redact(str(exc), self._secret))) from None
        choice = response.choices[0].message
        tool_calls: list[ToolCall] = []
        for call in choice.tool_calls or []:
            raw = call.function.arguments or "{}"
            try:
                arguments = json.loads(raw)
            except json.JSONDecodeError:
                arguments = {}
            if not isinstance(arguments, dict):
                arguments = {}
            tool_calls.append(ToolCall(id=call.id, name=call.function.name, arguments=arguments))
        usage = response.usage
        text = choice.content or ""
        if usage is None:
            prompt_tokens = estimate_tokens(json.dumps(messages))
            completion_tokens = estimate_tokens(text or json.dumps([call.arguments for call in tool_calls]))
            estimated = True
        else:
            prompt_tokens = int(usage.prompt_tokens or 0)
            completion_tokens = int(usage.completion_tokens or 0)
            estimated = False
        log.info(
            "chat stage tokens prompt=%s completion=%s estimated=%s",
            prompt_tokens,
            completion_tokens,
            estimated,
        )
        return ChatResponse(
            text=text,
            tool_calls=tool_calls,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated=estimated,
        )

    def embed(self, texts: list[str]) -> EmbedResponse:
        if not texts:
            return EmbedResponse(vectors=[], prompt_tokens=0, estimated=False)
        try:
            response = self._client.embeddings.create(model=self.embedding_model, input=texts)
        except Exception as exc:
            message = str(redact(str(exc), self._secret))
            lowered = message.lower()
            if "404" in lowered or "not found" in lowered or "embeddings" in lowered:
                raise LLMError(f"embeddings endpoint is unavailable: {message}") from None
            raise LLMError(message) from None
        vectors = [list(item.embedding) for item in response.data]
        usage = getattr(response, "usage", None)
        if usage is None:
            tokens = estimate_tokens("\n".join(texts))
            estimated = True
        else:
            tokens = int(getattr(usage, "total_tokens", 0) or getattr(usage, "prompt_tokens", 0) or 0)
            estimated = False
        log.info("embed tokens=%s estimated=%s count=%s", tokens, estimated, len(texts))
        return EmbedResponse(vectors=vectors, prompt_tokens=tokens, estimated=estimated)
