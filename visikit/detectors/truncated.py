"""Packet slicing: frames cut short before they reach the tool.

A broker that slices packets (to save bandwidth) sends frames shorter than the IP
header says they should be, so the payload the tool needs is missing.

A feed made mostly of small frames (for example a receive-only SPAN that sees only the ACKs of
a download) can hide slicing: few frames are long enough to be cut. So the share is also
measured against the frames longer than the slice length, and most of those being cut is
reported too.

Tool-aware: only tools that need the full payload (IDS, NDR) are harmed; for APM or
SIEM, slicing is a normal way to save bandwidth and is not reported.
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.05      # more than 5% of frames sliced is a fault
SYSTEMATIC = 0.5      # ...or most of the frames long enough to be cut, when there are enough of them
MIN_SLICED = 30
ETH_HEADER = 14


@detector
class Truncated:
    fault = "truncated"

    def run(self, ctx: FeedContext) -> list[Finding]:
        if not ctx.profile.needs_full_payload:
            return []
        rows = fields(ctx.pcap, ["frame.number", "frame.len", "ip.len", "ipv6.plen"])
        if not rows:
            return []
        sliced, lengths, real = [], [], []
        for row in rows:
            row += [""] * (4 - len(row))
            frame, flen, iplen, plen6 = row
            if not iplen and plen6:
                iplen = str(int(plen6) + 40)              # IPv6: payload length + fixed header
            if iplen:
                real.append(int(iplen) + ETH_HEADER)
            # The outer IP header states the packet's real length; a frame shorter than that was cut
            if iplen and int(iplen) > int(flen) - ETH_HEADER:
                sliced.append(int(frame))
                lengths.append(int(flen))
        share = len(sliced) / len(rows)
        if not sliced:
            return []
        slice_len = max(set(lengths), key=lengths.count)
        long_enough = sum(n > slice_len for n in real)
        of_long = len(sliced) / long_enough if long_enough else 0.0
        systematic = of_long > SYSTEMATIC and len(sliced) >= MIN_SLICED
        if share <= THRESHOLD and not systematic:
            return []
        extra = (f"; {of_long:.0%} of the {long_enough} frames longer than {slice_len} bytes were cut"
                 if share <= THRESHOLD else "")
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.2 or systematic else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=sliced[:20],
            detail=(f"{len(sliced)} of {len(rows)} frames are cut short ({share:.1%}), most to {slice_len} bytes; "
                    f"this {ctx.profile.tool_type} needs the full payload{extra}"),
        )]
