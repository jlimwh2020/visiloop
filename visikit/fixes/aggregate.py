"""Aggregate both directions of each link onto the same tool port."""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class Aggregate:
    fault = "one_way"
    action = "aggregate"
    stage = 10

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"inputs": "both TAP legs (A->B and B->A)", "hash": "symmetric_5tuple",
                           "one_way_session_share": finding.metric},
                   broker_config={"tool_port": ctx.feed,
                                  "map": {"inputs": ["tap_leg_a", "tap_leg_b"], "aggregate": True},
                                  "load_balance_hash": "symmetric_5tuple"})

    def simulate(self, pcaps, ctx, fix, workdir):
        # The broker already receives both legs (ingress); mapping both to the port rebuilds the feed
        return [ctx.ingress] if ctx.ingress else None
