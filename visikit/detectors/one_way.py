"""One-way traffic: share of TCP sessions where only one direction is seen (tshark -z conv,tcp / Zeek conn.log history).

Day 2: implement run().
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding


@detector
class OneWay:
    fault = "one_way"

    def run(self, ctx: FeedContext) -> list[Finding]:
        raise NotImplementedError
