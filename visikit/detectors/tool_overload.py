"""Tool overload: short traffic bursts faster than the tool's input port.

Averages hide microbursts, so traffic is measured in 1 ms intervals and the
peak is compared with the tool port speed from its profile.
"""
from collections import defaultdict

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

INTERVAL = 0.001      # seconds
THRESHOLD = 0.8       # peak above 80% of the port speed is a fault


def measure_bins(pcap: str):
    """Bytes per 1 ms interval, and the first frame number in each interval."""
    bins, first = defaultdict(int), {}
    for frame, t, length in fields(pcap, ["frame.number", "frame.time_relative", "frame.len"]):
        b = int(float(t) / INTERVAL)
        bins[b] += int(length)
        first.setdefault(b, int(frame))
    return bins, first


def peak_gbps(pcap: str) -> float:
    bins, _ = measure_bins(pcap)
    return max(bins.values()) * 8 / INTERVAL / 1e9 if bins else 0.0


@detector
class ToolOverload:
    fault = "tool_overload"

    def run(self, ctx: FeedContext) -> list[Finding]:
        bins, first = measure_bins(ctx.pcap)
        if not bins:
            return []
        peak_bin, peak_bytes = max(bins.items(), key=lambda kv: kv[1])
        peak_gbps = peak_bytes * 8 / INTERVAL / 1e9
        load = peak_gbps / ctx.profile.max_rate_gbps
        if load <= THRESHOLD:
            return []
        hot = sorted(b for b, v in bins.items() if v * 8 / INTERVAL / 1e9 > THRESHOLD * ctx.profile.max_rate_gbps)
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if load > 1.0 else "medium",
            metric=round(load, 3), threshold=THRESHOLD,
            evidence=[first[b] for b in hot[:20]],
            detail=(f"Peak {peak_gbps:.2f} Gbps in a 1 ms burst vs a {ctx.profile.max_rate_gbps:g} Gbps "
                    f"{ctx.profile.tool_type} port ({load:.0%} of capacity, {len(hot)} overloaded intervals)"),
        )]
