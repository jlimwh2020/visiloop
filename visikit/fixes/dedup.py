"""Deduplication on the packet broker."""
from visikit.core.registry import fix
from visikit.core.schema import FeedContext, Fix
from visikit.core.tools import run

WINDOW = 500


@fix
class Dedup:
    fault = "duplicates"

    def simulate(self, ctx: FeedContext, out_pcap: str) -> str:
        """Apply the fix to the capture, as the broker would."""
        run("editcap", ["-D", str(WINDOW), ctx.pcap, out_pcap])
        return out_pcap

    def config(self, ctx: FeedContext) -> Fix:
        return Fix(
            fault=self.fault, action="dedup",
            params={"window_packets": WINDOW},
            broker_config={"tool_port": ctx.feed, "dedup": {"enabled": True, "window_packets": WINDOW}},
        )
