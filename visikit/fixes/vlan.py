"""Preserve 802.1Q VLAN tags through the broker to the tool."""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class PreserveVlan:
    fault = "missing_vlan"
    action = "vlan"
    stage = 10

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"preserve_dot1q": True, "required_vlans": ctx.profile.required_vlans},
                   broker_config={"tool_port": ctx.feed, "vlan": {"strip": False, "preserve_dot1q": True},
                                  "ingress": {"source": "trunk or TAP carrying tagged frames"}})

    def simulate(self, pcaps, ctx, fix, workdir):
        return [ctx.ingress] if ctx.ingress else None
