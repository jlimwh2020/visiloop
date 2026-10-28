"""Packet slicing: frames cut short before they reach the tool.

A broker that slices packets (to save bandwidth) sends frames shorter than the IP
header says they should be, so the payload the tool needs is missing.

Tool-aware: only tools that need the full payload (IDS, NDR) are harmed; for APM or
SIEM, slicing is a normal way to save bandwidth and is not reported.
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.05      # more than 5% of frames sliced is a fault
ETH_HEADER = 14


@detector
class Truncated:
    fault = "truncated"

    def run(self, ctx: FeedContext) -> list[Finding]:
        if not ctx.profile.needs_full_payload:
            return []
        rows = fields(ctx.pcap, ["frame.number", "frame.len", "ip.len"])
        if not rows:
            return []
        sliced, lengths = [], []
        for row in rows:
            row += [""] * (3 - len(row))
            frame, flen, iplen = row
            # The outer IP header states the packet's real length; a frame shorter than that was cut
            if iplen and int(iplen) > int(flen) - ETH_HEADER:
                sliced.append(int(frame))
                lengths.append(int(flen))
        share = len(sliced) / len(rows)
        if share <= THRESHOLD:
            return []
        slice_len = max(set(lengths), key=lengths.count)
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.2 else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=sliced[:20],
            detail=(f"{len(sliced)} of {len(rows)} frames are cut short ({share:.1%}), most to {slice_len} bytes; "
                    f"this {ctx.profile.tool_type} needs the full payload"),
        )]
