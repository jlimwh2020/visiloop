"""Encrypted share: how much of the feed the tool cannot inspect.

Counts bytes in TLS or QUIC traffic (by dissector, or to or from port 443) and compares
the share with what this tool type can tolerate (profile.max_encrypted_share).
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields


def _is_encrypted(protocols: str, ports: list[str]) -> bool:
    protos = protocols.split(":")
    return "tls" in protos or "quic" in protos or "443" in ports


@detector
class EncryptedShare:
    fault = "encrypted_share"

    def run(self, ctx: FeedContext) -> list[Finding]:
        # Both ports of the innermost header ("l"), so every packet of a TLS session counts, including
        # client-to-server acknowledgements, and tunnelled traffic is judged by what is inside the tunnel
        names = ["frame.number", "frame.len", "frame.protocols", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
        rows = fields(ctx.pcap, names, occurrence="l")
        total = enc = 0
        sample = []
        for row in rows:
            row += [""] * (len(names) - len(row))
            frame, length, protos, *ports = row
            total += int(length)
            if _is_encrypted(protos, ports):
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
