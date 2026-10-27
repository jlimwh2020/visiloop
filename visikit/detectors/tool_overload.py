"""Tool overload: peak traffic rate per short interval vs the tool port speed (tshark -z io,stat).

Day 2: implement run().
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding


@detector
class ToolOverload:
    fault = "tool_overload"

    def run(self, ctx: FeedContext) -> list[Finding]:
        raise NotImplementedError
