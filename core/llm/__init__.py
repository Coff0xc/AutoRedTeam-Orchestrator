"""
core.llm — 统一 LLM Provider 接口

支持 OpenAI / Anthropic / Ollama / DeepSeek，通过 LiteLLM 或直接 SDK 调用。
当无 LLM 可用时，所有方法返回 None (graceful degradation)。

Usage:
    from core.llm import get_llm

    llm = get_llm()
    if llm.available:
        result = llm.complete("分析这个漏洞...")
"""

from .provider import LLMProvider, get_llm, reset_llm

__all__ = [
    "LLMProvider",
    "get_llm",
    "reset_llm",
]
