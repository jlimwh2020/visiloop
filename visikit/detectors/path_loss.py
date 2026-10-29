"""Path checks from interface counters: where along the feed's path packets are lost.

Needs counters (ctx.counters), not a capture. Compares neighbouring hops (SPAN source and
destination, broker input and output, the tool's interface) and reads each device's own
discard and error counters, so the finding names the exact device and port.
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.counters import analyse

LOSS_THRESHOLD = 0.001          # more than 0.1% of packets lost at one place is a fault
ERROR_THRESHOLD = 0.00001       # damaged frames above 0.001% point to a bad cable or optic


@detector
class PathLoss:
    fault = "path_loss"
    source = "counters"

    def run(self, ctx: FeedContext) -> list[Finding]:
        if ctx.counters is None:
            return []
        issues = [i for i in analyse(ctx.counters, LOSS_THRESHOLD) if i["kind"] != "link_errors"]
        if not issues:
            return []
        worst = issues[0]
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if worst["share"] > 0.01 else "medium",
            metric=worst["share"], threshold=LOSS_THRESHOLD,
            detail="; ".join(f"{i['detail']} ({i['share']:.2%} lost)" for i in issues[:3]),
            location=f"{worst['device']} {worst['port']}".strip() or worst["hop"],
        )]


@detector
class LinkErrors:
    fault = "link_errors"
    source = "counters"

    def run(self, ctx: FeedContext) -> list[Finding]:
        if ctx.counters is None:
            return []
        issues = [i for i in analyse(ctx.counters, 0) if i["kind"] == "link_errors" and i["share"] > ERROR_THRESHOLD]
        if not issues:
            return []
        worst = issues[0]
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if worst["share"] > 0.001 else "medium",
            metric=worst["share"], threshold=ERROR_THRESHOLD,
            detail="; ".join(i["detail"] for i in issues[:3]),
            location=f"{worst['device']} {worst['port']}".strip() or worst["hop"],
        )]
