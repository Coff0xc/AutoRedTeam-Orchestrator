"""
统一 LLM Provider — 支持 OpenAI / Anthropic / Ollama / DeepSeek / OrcaRouter

通过 LiteLLM 统一接口调用 300+ 模型，或直接使用 OpenAI/Anthropic SDK。
当无 LLM 可用时，所有方法返回 None (graceful degradation)。

配置 (环境变量):
    AUTORT_LLM_PROVIDER: openai / anthropic / ollama / deepseek / orcarouter / none
    AUTORT_LLM_MODEL:    模型名 (默认按 provider 自动选择)
    AUTORT_LLM_API_KEY:  API Key；未设置时回退到该 provider 对应的环境变量
    AUTORT_LLM_BASE_URL: 自定义 base URL (Ollama: http://localhost:11434)

OrcaRouter Cyber Inference (provider id ``orcarouter``) is a named provider for
authorized red-team/blue-team work. Its relay is OpenAI-compatible at
``https://api.orcarouter.ai/v1``. Credentials come from the credential seam in
``core.llm.orcarouter``: either an exported ``sk-orca-…`` key (environment or
the user credential file) or an OAuth 2.0 + PKCE login. HTTP 401 from the relay
marks the exact rejected credential generation for reauthentication; there is
no refresh grant.

多 provider 路径依赖 litellm；litellm 未安装时只有 openai/anthropic 直连 SDK 可用，
ollama/deepseek 会因缺少后端而静默降级（返回 None）。
"""

import logging
import os
from typing import Any, Dict, List, Optional

from .orcarouter import DEFAULT_MODEL as ORCAROUTER_DEFAULT_MODEL
from .orcarouter import (
    OrcaCredential,
    PkceCredentialSource,
    api_base_url,
    resolve_credential,
)

logger = logging.getLogger(__name__)

# LiteLLM 为可选依赖
try:
    import litellm

    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False

# 各 provider 的默认模型
_DEFAULT_MODELS: Dict[str, str] = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-20250514",
    "ollama": "llama3.1",
    "deepseek": "deepseek-chat",
    "orcarouter": ORCAROUTER_DEFAULT_MODEL,
}

# LiteLLM 模型名前缀映射
_LITELLM_PREFIX: Dict[str, str] = {
    "openai": "",
    "anthropic": "",
    "ollama": "ollama/",
    "deepseek": "deepseek/",
    # OrcaRouter speaks the OpenAI wire format; litellm needs the explicit
    # openai/ prefix so it honours api_base instead of vendor routing.
    "orcarouter": "openai/",
}

# AUTORT_LLM_API_KEY 未设置时，按 provider 回退到对应的厂商环境变量
_PROVIDER_KEY_ENV: Dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "orcarouter": "ORCAROUTER_API_KEY",
}


def _llm_config() -> Any:
    """Load the ``llm`` config section lazily (env > YAML > defaults)."""
    try:
        from core.config import get_config

        return get_config().llm
    except Exception:  # pragma: no cover - configuration is optional
        return None


class LLMProvider:
    """统一 LLM 调用接口

    使用 LiteLLM 支持 300+ 模型，或直接调用 OpenAI/Anthropic SDK。
    当无 LLM 可用时，所有方法返回 None (graceful degradation)。
    """

    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None) -> None:
        self._credential: Optional[OrcaCredential] = None
        cfg = _llm_config()
        cfg_provider = getattr(cfg, "provider", "") if cfg is not None else ""
        provider_override = (provider or "").strip().lower()
        model_override = (model or "").strip()

        self.provider: str = (
            provider_override
            or (os.environ.get("AUTORT_LLM_PROVIDER") or cfg_provider or "none").lower()
        )

        cfg_model = getattr(cfg, "model", "") if cfg is not None else ""
        cfg_api_key = getattr(cfg, "api_key", "") if cfg is not None else ""
        cfg_base_url = getattr(cfg, "base_url", "") if cfg is not None else ""

        if self.provider == "orcarouter":
            # Credential seam: API key (env/user file) — the PKCE adapter writes
            # to the same store, so downstream code does not care which one ran.
            self._credential = resolve_credential()
            self.api_key: str = (
                os.environ.get("AUTORT_LLM_API_KEY", "")
                or cfg_api_key
                or (self._credential.api_key if self._credential else "")
            )
            stored_model = self._credential.model if self._credential else ""
            self.model: str = (
                model_override
                or os.environ.get("AUTORT_LLM_MODEL", "")
                or cfg_model
                or stored_model
                or ORCAROUTER_DEFAULT_MODEL
            )
            self.base_url: str = (
                os.environ.get("AUTORT_LLM_BASE_URL", "") or cfg_base_url or api_base_url()
            )
            self._available = bool(self.api_key) and (LITELLM_AVAILABLE or self._has_direct_sdk())
        else:
            self.model = model_override or os.environ.get(
                "AUTORT_LLM_MODEL",
                cfg_model or _DEFAULT_MODELS.get(self.provider, "gpt-4o-mini"),
            )
            self.api_key = os.environ.get(
                "AUTORT_LLM_API_KEY",
                cfg_api_key or os.environ.get(_PROVIDER_KEY_ENV.get(self.provider, ""), ""),
            )
            self.base_url = os.environ.get("AUTORT_LLM_BASE_URL", cfg_base_url)
            self._available = self.provider != "none" and (
                LITELLM_AVAILABLE or self._has_direct_sdk()
            )

        if self._available:
            logger.info("LLM Provider 初始化: %s/%s", self.provider, self.model)
        elif self.provider == "orcarouter":
            logger.info(
                "OrcaRouter provider selected but no credential found; "
                "run `autort llm connect` or set ORCAROUTER_API_KEY"
            )
        else:
            logger.debug("LLM Provider 未配置, AI 增强功能禁用")

    @property
    def credential(self) -> Optional[OrcaCredential]:
        """The resolved OrcaRouter credential, if this provider uses one."""
        return self._credential

    @property
    def available(self) -> bool:
        """LLM 是否可用"""
        return self._available

    def _has_direct_sdk(self) -> bool:
        """检查是否有直接 SDK (不依赖 litellm)"""
        if self.provider in ("openai", "orcarouter"):
            try:
                import openai  # noqa: F401

                return True
            except ImportError:
                return False
        if self.provider == "anthropic":
            try:
                import anthropic  # noqa: F401

                return True
            except ImportError:
                return False
        return False

    def complete(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> Optional[str]:
        """同步调用 LLM

        Args:
            prompt: 用户提示词
            system: 系统提示词 (可选)
            temperature: 温度参数
            max_tokens: 最大生成 token 数

        Returns:
            LLM 响应文本，或 None (不可用时)
        """
        if not self._available:
            return None
        try:
            # OrcaRouter goes through the OpenAI SDK directly so the relay base
            # URL and bearer key are used exactly as configured.
            if self.provider == "orcarouter" and self._has_direct_sdk():
                return self._orcarouter_call(prompt, system, temperature, max_tokens)
            if LITELLM_AVAILABLE:
                return self._litellm_call(prompt, system, temperature, max_tokens)
            return self._direct_call(prompt, system, temperature, max_tokens)
        except Exception as e:
            logger.warning("LLM 调用失败: %s", self._redact(str(e)))
            return None

    def complete_json(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        schema: type | None = None,
    ) -> Optional[Dict[str, Any]]:
        """调用 LLM 并期望 JSON 响应

        Args:
            prompt: 用户提示词
            system: 系统提示词 (可选)
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            schema: 可选 Pydantic BaseModel 子类，用于验证响应格式

        Returns:
            解析后的 dict，或 None (不可用/解析失败/schema 验证失败)
        """
        import json

        result = self.complete(prompt, system, temperature, max_tokens)
        if result is None:
            return None
        # 尝试提取 JSON 块
        try:
            # 处理 ```json ... ``` 格式
            if "```json" in result:
                start = result.index("```json") + 7
                end = result.index("```", start)
                result = result[start:end].strip()
            elif "```" in result:
                start = result.index("```") + 3
                end = result.index("```", start)
                result = result[start:end].strip()
            parsed = json.loads(result)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("LLM JSON 解析失败: %s", e)
            return None

        # 如果提供了 Pydantic schema，执行验证
        if schema is not None:
            try:
                validated = schema.model_validate(parsed)  # type: ignore[attr-defined]
                return validated.model_dump()  # type: ignore[no-any-return]
            except Exception as e:
                logger.warning("LLM 响应 schema 验证失败 (%s): %s", schema.__name__, e)
                return None

        return parsed  # type: ignore[no-any-return]

    def _litellm_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> Optional[str]:
        """通过 LiteLLM 统一接口调用"""
        prefix = _LITELLM_PREFIX.get(self.provider, "")
        model_name = f"{prefix}{self.model}"

        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs: Dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["api_base"] = self.base_url

        response = litellm.completion(**kwargs)
        return response.choices[0].message.content  # type: ignore[no-any-return]

    def _direct_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> Optional[str]:
        """直接 SDK 调用 (不依赖 litellm)"""
        if self.provider == "openai":
            return self._openai_call(prompt, system, temperature, max_tokens)
        elif self.provider == "anthropic":
            return self._anthropic_call(prompt, system, temperature, max_tokens)
        return None

    def _redact(self, message: str) -> str:
        """Keep credentials out of logs and error strings."""
        if self.api_key and self.api_key in message:
            return message.replace(self.api_key, "<redacted>")
        return message

    def _orcarouter_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> str:
        """OpenAI-wire call to the OrcaRouter Cyber Inference relay."""
        import openai

        client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url or api_base_url(),
        )
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            resp = client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as exc:
            self._handle_orcarouter_failure(exc)
            raise
        return resp.choices[0].message.content  # type: ignore[return-value]

    def _handle_orcarouter_failure(self, exc: Exception) -> None:
        """Terminal 401 handling: flag the rejected credential generation.

        OrcaRouter keys are durable and there is no refresh grant, so the only
        correct reaction is reauthentication — never a retry loop and never a
        silent refresh.
        """
        status = getattr(exc, "status_code", None)
        if status != 401:
            return
        logger.warning(
            "OrcaRouter rejected the credential (HTTP 401). Run `autort llm connect` "
            "or update ORCAROUTER_API_KEY; stored keys are reused until revoked."
        )
        if self._credential is None:
            return
        try:
            PkceCredentialSource().mark_needs_reauth(self._credential)
        except Exception:  # pragma: no cover - store failures must not mask the 401
            logger.debug("Could not persist the needs-reauth flag")

    def _openai_call(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        """OpenAI SDK 直接调用"""
        import openai

        client = openai.OpenAI(api_key=self.api_key or None)
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore[arg-type]
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content  # type: ignore[return-value]

    def _anthropic_call(self, prompt: str, system: str, temperature: float, max_tokens: int) -> str:
        """Anthropic SDK 直接调用"""
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key or None)
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        resp = client.messages.create(**kwargs)
        return resp.content[0].text  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# 全局单例 (线程安全)
# ---------------------------------------------------------------------------
import threading

_provider: Optional[LLMProvider] = None
_provider_lock = threading.Lock()


def get_llm() -> LLMProvider:
    """获取全局 LLMProvider 单例 (线程安全)"""
    global _provider
    if _provider is not None:
        return _provider
    with _provider_lock:
        if _provider is None:
            _provider = LLMProvider()
    return _provider


def reset_llm() -> None:
    """重置全局 LLMProvider (用于测试或配置变更)"""
    global _provider
    _provider = None
