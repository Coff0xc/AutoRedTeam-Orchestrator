import pytest
from urllib.parse import urlsplit, parse_qsl

from core.stealth.controller import (
    RequestContext,
    StealthConfig,
    StealthLevel,
    TrafficObfuscation,
    DomainFronting,
)


@pytest.mark.asyncio
async def test_traffic_obfuscation_preserves_fragment():
    context = RequestContext(url="https://example.com/path?foo=1#frag")
    obfuscation = TrafficObfuscation()
    config = StealthConfig(level=StealthLevel.HIGH)

    result = await obfuscation.apply(context, config)

    parts = urlsplit(result.url)
    assert parts.fragment == "frag"

    query_params = dict(parse_qsl(parts.query, keep_blank_values=True))
    assert query_params.get("foo") == "1"
    assert "_" in query_params


@pytest.mark.asyncio
async def test_domain_fronting_rewrites_netloc_only():
    context = RequestContext(url="https://origin.example.com/path/origin.example.com")
    fronting = DomainFronting()
    config = StealthConfig(level=StealthLevel.MEDIUM)
    config.use_domain_fronting = True
    config.fronting_domain = "front.example.net"

    result = await fronting.apply(context, config)

    parts = urlsplit(result.url)
    assert parts.netloc == "front.example.net"
    assert parts.path == "/path/origin.example.com"
    assert result.headers.get("Host") == "origin.example.com"
