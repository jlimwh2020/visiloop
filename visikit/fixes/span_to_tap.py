"""Feed the tool from a lossless passive TAP instead of a SPAN session."""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class ReplaceSpanWithTap:
    fault = "packet_drops"
    action = "replace_span_with_tap"
    stage = 10

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"source": "passive TAP on the monitored link", "replaces": "SPAN session",
                           "measured_loss_evidence": finding.metric,
                           "also_check": "broker egress drop counters on this tool port"},
                   broker_config={"tool_port": ctx.feed, "map": {"inputs": ["tap_leg_a", "tap_leg_b"]},
                                  "remove_inputs": ["span_session"]})

    def simulate(self, pcaps, ctx, fix, workdir):
        return [ctx.ingress] if ctx.ingress else None
