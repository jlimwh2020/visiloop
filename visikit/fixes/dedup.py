"""Deduplication on the packet broker (removes copies from overlapping TAP/SPAN inputs)."""
import os

from visikit.core.registry import fix
from visikit.core.schema import Fix
from visikit.core.tools import run

WINDOW = 500


@fix
class Dedup:
    fault = "duplicates"
    action = "dedup"
    stage = 20

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"window_packets": WINDOW, "measured_duplicate_rate": finding.metric},
                   broker_config={"tool_port": ctx.feed, "dedup": {"enabled": True, "window_packets": WINDOW}})

    def simulate(self, pcaps, ctx, fix, workdir):
        out = []
        for i, p in enumerate(pcaps):
            dst = os.path.join(workdir, f"dedup_{i}.pcap")
            run("editcap", ["-D", str(WINDOW), p, dst])
            out.append(dst)
        return out
