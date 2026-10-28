"""Oversize frames: raise the MTU on the broker egress and the tool, or slice to fit.

This needs a change on the tool itself, so it cannot be verified offline and is
reported as advice.
"""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class MtuAdvice:
    fault = "oversize"
    action = "mtu_advice"
    stage = 90

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"oversize_share": finding.metric, "tool_max_frame_bytes": ctx.profile.max_frame_bytes,
                           "recommended": "set MTU 9216 on the broker egress port and the tool's capture interface",
                           "alternative": ("slice frames to the tool's maximum" if not ctx.profile.needs_full_payload
                                           else "if the tool cannot take jumbo frames, move this traffic to a tool that can")},
                   broker_config={"tool_port": ctx.feed, "mtu": 9216})

    def simulate(self, pcaps, ctx, fix, workdir):
        return None
