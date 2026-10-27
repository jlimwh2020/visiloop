"""Missing VLANs: required VLAN IDs absent, or untagged traffic (tshark field vlan.id).

Day 2: implement run().
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding


@detector
class MissingVlan:
    fault = "missing_vlan"

    def run(self, ctx: FeedContext) -> list[Finding]:
        raise NotImplementedError
