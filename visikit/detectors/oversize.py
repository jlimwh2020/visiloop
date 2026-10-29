"""Oversize frames: frames larger than the tool's network card accepts.

Jumbo frames (data centre traffic, storage, backups) above the tool's maximum frame size
are silently dropped by its network card, so the tool never sees them.

Tool-aware: compared with the tool's own maximum (1518 bytes for a standard port,
9216 bytes for a jumbo-capable one).
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.01      # more than 1% of frames too large is a fault


@detector
class Oversize:
    fault = "oversize"

    def run(self, ctx: FeedContext) -> list[Finding]:
        limit = ctx.profile.max_frame_bytes
        rows = fields(ctx.pcap, ["frame.number", "frame.len"])
        if not rows:
            return []
        big = [(int(f), int(n)) for f, n in rows if int(n) > limit]
        share = len(big) / len(rows)
        if share <= THRESHOLD:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.05 else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=[f for f, _ in big[:20]],
            detail=(f"{len(big)} of {len(rows)} frames ({share:.1%}) are larger than the {limit}-byte maximum of "
                    f"this {ctx.profile.tool_type} port (largest {max(n for _, n in big)} bytes); its network card drops them. "
                    + ("This tool needs the full payload, so trimming frames to fit is not an option."
                       if ctx.profile.needs_full_payload else
                       "This tool does not need the payload, so trimming frames to fit on the broker is an option.")),
        )]
