"""One-way traffic: TCP sessions where packets are seen from only one side.

Typical causes: a SPAN port mirroring RX only, a TAP feeding just one direction,
or asymmetric routing where the return path crosses an unmonitored link.

Tool-aware: a tool whose profile does not need both directions (for example a
SIEM taking connection records) is not harmed by one-way traffic, so it is not
reported as a fault there. Muse Spark pointed out this gap in the benchmark suite.
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
        if not ctx.profile.needs_both_directions:
            return []
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
        severity = "high"          # this tool needs both directions, so any material share hurts it
        return [Finding(
            fault=self.fault, feed=ctx.feed, severity=severity,
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=sorted(first_frame[s] for s in one_sided)[:20],
            detail=f"{len(one_sided)} of {len(senders)} TCP sessions show only one direction ({share:.1%})",
        )]
