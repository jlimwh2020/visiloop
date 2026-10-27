"""Missing VLANs: required VLANs absent, or traffic arriving untagged.

If the broker strips tags or a SPAN session covers the wrong VLANs, the tool
cannot tell segments apart or never sees some of them.
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

UNTAGGED_THRESHOLD = 0.05


@detector
class MissingVlan:
    fault = "missing_vlan"

    def run(self, ctx: FeedContext) -> list[Finding]:
        required = set(ctx.profile.required_vlans)
        if not required:
            return []
        rows = fields(ctx.pcap, ["frame.number", "vlan.id"])
        if not rows:
            return []
        seen, untagged = set(), []
        for row in rows:
            vid = row[1] if len(row) > 1 else ""
            if vid:
                seen.add(int(vid))
            else:
                untagged.append(int(row[0]))
        missing = sorted(required - seen)
        untagged_share = len(untagged) / len(rows)
        if not missing and untagged_share <= UNTAGGED_THRESHOLD:
            return []
        parts = []
        if missing:
            parts.append(f"required VLAN(s) {', '.join(map(str, missing))} not seen")
        if untagged_share > UNTAGGED_THRESHOLD:
            parts.append(f"{untagged_share:.0%} of packets untagged")
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if missing else "medium",
            metric=round(len(missing) / len(required), 4), threshold=0.0,
            evidence=untagged[:20],
            detail="; ".join(parts),
        )]
