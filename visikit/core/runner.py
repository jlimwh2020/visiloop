"""Run every registered detector on a feed."""
from .registry import load_plugins
from .schema import FeedContext, Finding


def check_feed(ctx: FeedContext) -> list[Finding]:
    detectors, _ = load_plugins()
    findings: list[Finding] = []
    for name, cls in detectors.items():
        try:
            findings.extend(cls().run(ctx))
        except NotImplementedError:
            pass  # stub detector, not built yet
    return findings
