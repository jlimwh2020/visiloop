"""One-way traffic: TCP sessions where packets are seen from only one side.

Typical causes: a SPAN port mirroring RX only, a TAP feeding just one direction,
or asymmetric routing where the return path crosses an unmonitored link.
"""
from collections import defaultdict

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.10      # more than 10% one-sided sessions is a fault


@detector
class OneWay:
    fault = "one_way"

    def run(self, ctx: FeedContext) -> list[Finding]:
        senders = defaultdict(set)
        first_frame = {}
        for frame, stream, src in fields(ctx.pcap, ["frame.number", "tcp.stream", "ip.src"], "tcp"):
            senders[stream].add(src)
            first_frame.setdefault(stream, int(frame))
        if not senders:
            return []
        one_sided = [s for s, ips in senders.items() if len(ips) == 1]
        share = len(one_sided) / len(senders)
        if share <= THRESHOLD:
            return []
        severity = "high" if (share > 0.3 or ctx.profile.needs_both_directions) else "medium"
        return [Finding(
            fault=self.fault, feed=ctx.feed, severity=severity,
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=sorted(first_frame[s] for s in one_sided)[:20],
            detail=f"{len(one_sided)} of {len(senders)} TCP sessions show only one direction ({share:.1%})",
        )]
