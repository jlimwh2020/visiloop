"""Tunnel encapsulation: traffic reaching the tool still wrapped in ERSPAN, GRE or VXLAN.

Remote SPAN (ERSPAN), GRE mirror tunnels and cloud traffic mirroring (VXLAN) deliver
copies inside a tunnel. If the broker does not strip the tunnel headers, most tools see
only the tunnel endpoints and cannot analyse the traffic inside.
"""
from collections import Counter

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.10      # more than 10% of frames encapsulated is a fault
TUNNELS = {"erspan": "ERSPAN", "vxlan": "VXLAN", "geneve": "GENEVE", "gre": "GRE"}


@detector
class Tunnel:
    fault = "tunnel"

    def run(self, ctx: FeedContext) -> list[Finding]:
        rows = fields(ctx.pcap, ["frame.number", "frame.protocols"])
        if not rows:
            return []
        hits, kinds = [], Counter()
        for row in rows:
            protos = (row[1] if len(row) > 1 else "").split(":")
            kind = next((name for key, name in TUNNELS.items() if key in protos), None)
            if kind:
                hits.append(int(row[0]))
                kinds[kind] += 1
        share = len(hits) / len(rows)
        if share <= THRESHOLD:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.3 else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=hits[:20],
            detail=(f"{len(hits)} of {len(rows)} frames ({share:.1%}) arrive inside a tunnel ("
                    + ", ".join(f"{k} {v}" for k, v in kinds.most_common()) + ")"),
        )]
