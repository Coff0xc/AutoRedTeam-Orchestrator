"""
统一 LLM Provider — 支持 OpenAI / Anthropic / Ollama / DeepSeek

通过 LiteLLM 统一接口调用 300+ 模型，或直接使用 OpenAI/Anthropic SDK。
当无 LLM 可用时，所有方法返回 None (graceful degradation)。

配置 (环境变量):
    AUTORT_LLM_PROVIDER: openai / anthropic / ollama / deepseek / none (默认 none)
    AUTORT_LLM_MODEL:    模型名 (默认按 provider 自动选择)
    AUTORT_LLM_API_KEY:  API Key
    AUTORT_LLM_BASE_URL: 自定义 base URL (Ollama: http://localhost:11434)
"""

import logging
import os
from typing import Any, Dict, List, Optional

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
}

# LiteLLM 模型名前缀映射
_LITELLM_PREFIX: Dict[str, str] = {
    "openai": "",
    "anthropic": "",
    "ollama": "ollama/",
    "deepseek": "deepseek/",
}


class LLMProvider:
    """统一 LLM 调用接口

    使用 LiteLLM 支持 300+ 模型，或直接调用 OpenAI/Anthropic SDK。
    当无 LLM 可用时，所有方法返回 None (graceful degradation)。
    """

    def __init__(self) -> None:
        self.provider: str = os.environ.get("AUTORT_LLM_PROVIDER", "none").lower()
        self.model: str = os.environ.get(
            "AUTORT_LLM_MODEL", _DEFAULT_MODELS.get(self.provider, "gpt-4o-mini")
        )
        self.api_key: str = os.environ.get(
            "AUTORT_LLM_API_KEY", os.environ.get("OPENAI_API_KEY", "")
        )
        self.base_url: str = os.environ.get("AUTORT_LLM_BASE_URL", "")
        self._available: bool = self.provider != "none" and (
            LITELLM_AVAILABLE or self._has_direct_sdk()
        )

        if self._available:
            logger.info("LLM Provider 初始化: %s/%s", self.provider, self.model)
        else:
            logger.debug("LLM Provider 未配置, AI 增强功能禁用")

    @property
    def available(self) -> bool:
        """LLM 是否可用"""
        return self._available

    def _has_direct_sdk(self) -> bool:
        """检查是否有直接 SDK (不依赖 litellm)"""
        if self.provider == "openai":
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
            if LITELLM_AVAILABLE:
                return self._litellm_call(prompt, system, temperature, max_tokens)
            else:
                return self._direct_call(prompt, system, temperature, max_tokens)
        except Exception as e:
            logger.warning("LLM 调用失败: %s", e)
            return None

    def complete_json(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ) -> Optional[Dict[str, Any]]:
        """调用 LLM 并期望 JSON 响应

        Returns:
            解析后的 dict，或 None (不可用/解析失败)
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
            return json.loads(result)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("LLM JSON 解析失败: %s", e)
            return None

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
        return response.choices[0].message.content

    def _direct_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> Optional[str]:
        """直接 SDK 调用 (不依赖 litellm)"""
        if self.provider == "openai":
            return self._openai_call(prompt, system, temperature, max_tokens)
        elif self.provider == "anthropic":
            return self._anthropic_call(prompt, system, temperature, max_tokens)
        return None

    def _openai_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> str:
        """OpenAI SDK 直接调用"""
        import openai

        client = openai.OpenAI(api_key=self.api_key or None)
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content

    def _anthropic_call(
        self, prompt: str, system: str, temperature: float, max_tokens: int
    ) -> str:
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
        return resp.content[0].text


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
