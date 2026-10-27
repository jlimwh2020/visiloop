"""Encrypted share: how much of the feed the tool cannot inspect.

Counts bytes in TLS or QUIC traffic (by dissector, or on port 443) and compares
the share with what this tool type can tolerate (profile.max_encrypted_share).
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields


def _is_encrypted(protocols: str, tport: str, uport: str) -> bool:
    protos = protocols.split(":")
    return "tls" in protos or "quic" in protos or tport == "443" or uport == "443"


@detector
class EncryptedShare:
    fault = "encrypted_share"

    def run(self, ctx: FeedContext) -> list[Finding]:
        rows = fields(ctx.pcap, ["frame.number", "frame.len", "frame.protocols", "tcp.port", "udp.port"])
        total = enc = 0
        sample = []
        for row in rows:
            row += [""] * (5 - len(row))
            frame, length, protos, tport, uport = row
            total += int(length)
            if _is_encrypted(protos, tport, uport):
                enc += int(length)
                if len(sample) < 20:
                    sample.append(int(frame))
        if total == 0:
            return []
        share = enc / total
        limit = ctx.profile.max_encrypted_share
        if share <= limit:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > min(limit + 0.2, 0.95) else "medium",
            metric=round(share, 4), threshold=limit,
            evidence=sample,
            detail=f"{share:.0%} of bytes are encrypted; this {ctx.profile.tool_type} tolerates about {limit:.0%}",
        )]
