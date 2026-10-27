"""Encrypted share: TLS/QUIC share of bytes vs the tool's limit (tshark -z io,phs).

Day 2: implement run().
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding


@detector
class EncryptedShare:
    fault = "encrypted_share"

    def run(self, ctx: FeedContext) -> list[Finding]:
        raise NotImplementedError
