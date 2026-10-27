"""Duplicate packets: compare the packet count before and after editcap's dedup."""
import os
import tempfile

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import packet_count, run

THRESHOLD = 0.05      # more than 5% duplicates is a fault
WINDOW = 500          # look back this many packets for a duplicate


@detector
class Duplicates:
    fault = "duplicates"

    def run(self, ctx: FeedContext) -> list[Finding]:
        before = packet_count(ctx.pcap)
        if before == 0:
            return []
        with tempfile.TemporaryDirectory() as tmp:
            deduped = os.path.join(tmp, "dedup.pcap")
            run("editcap", ["-D", str(WINDOW), ctx.pcap, deduped])
            after = packet_count(deduped)
        rate = (before - after) / before
        if rate <= THRESHOLD:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if rate > 0.2 else "medium",
            metric=round(rate, 4), threshold=THRESHOLD,
            detail=f"{before - after} of {before} packets are duplicates ({rate:.1%})",
        )]
