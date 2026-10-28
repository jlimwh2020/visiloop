"""Turn packet slicing off on the tool port, so the tool receives full packets."""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class DisableSlicing:
    fault = "truncated"
    action = "disable_slicing"
    stage = 10

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"sliced_share": finding.metric, "tool_needs_full_payload": ctx.profile.needs_full_payload,
                           "note": "if bandwidth is the reason for slicing, load balance or filter instead"},
                   broker_config={"tool_port": ctx.feed, "packet_slicing": {"enabled": False}})

    def simulate(self, pcaps, ctx, fix, workdir):
        # The broker receives full packets (ingress); without slicing it forwards them whole
        return [ctx.ingress] if ctx.ingress else None
