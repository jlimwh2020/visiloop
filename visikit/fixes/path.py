"""Fixes for loss and errors found from interface counters, chosen by where the problem is.

Counters cannot be replayed through the simulated broker, so these are advice; VisiLoop
verifies them by reading the counters again after the change (continuous mode does this).
"""
import math

from visikit.core.registry import fix
from visikit.core.schema import Fix
from visikit.counters import analyse

TARGET = 0.7          # size tool groups to 70% of port speed, as the load-balance fix does


def _worst(ctx, kinds):
    issues = [i for i in analyse(ctx.counters, 0) if i["kind"] in kinds] if ctx.counters else []
    return issues[0] if issues else None


@fix
class PathLossFix:
    fault = "path_loss"
    action = "check_link"
    stage = 95

    def config(self, ctx, finding):
        w = _worst(ctx, {"span_oversubscribed", "egress_discards", "ingress_discards", "link_loss"}) or {}
        kind, where = w.get("kind"), finding.location or w.get("hop", "")
        if kind == "span_oversubscribed" or (kind == "egress_discards" and w.get("role") == "span_dest"):
            action, params = "replace_span_with_tap", {
                "where": where, "why": "the SPAN destination port cannot carry everything mirrored into it",
                "offered_gbps": w.get("offered_gbps"),
                "alternative": "mirror fewer ports or one direction per session, or use a faster SPAN destination"}
        elif kind == "egress_discards" and w.get("role") == "broker_out":
            speed = w.get("speed_gbps") or ctx.profile.max_rate_gbps
            ports = max(2, math.ceil((w.get("offered_gbps") or 0) / (TARGET * speed)) + 1)
            action, params = "load_balance", {
                "where": where, "ports": ports, "port_speed_gbps": speed, "hash": "symmetric_5tuple",
                "why": "the broker tool port is congested; average load understates the bursts, so one spare port is added",
                "alternative": f"one {math.ceil((w.get('offered_gbps') or 0) / TARGET / 10) * 10 or 10:g} Gbps tool port"}
        elif kind == "ingress_discards" and w.get("role") == "tool_in":
            action, params = "tool_capacity", {
                "where": where, "why": "the tool's capture interface drops what it receives",
                "recommended": "check the tool's capture card and CPU, or spread the feed over more tool instances"}
        else:
            action, params = "check_link", {
                "where": where, "why": "packets leave one device but do not arrive at the next",
                "recommended": "inspect the cable and optics between them; look for an unmonitored device in the path"}
        return Fix(self.fault, action, params={**params, "measured_loss": finding.metric},
                   broker_config={"location": where, "change": action})

    def simulate(self, pcaps, ctx, fix, workdir):
        return None


@fix
class LinkErrorsFix:
    fault = "link_errors"
    action = "check_link"
    stage = 95

    def config(self, ctx, finding):
        return Fix(self.fault, "check_link",
                   params={"where": finding.location, "error_rate": finding.metric,
                           "recommended": "replace the patch cable and clean or replace the optics on this link; "
                                          "check speed and duplex settings match on both ends"},
                   broker_config={"location": finding.location, "change": "check_link"})

    def simulate(self, pcaps, ctx, fix, workdir):
        return None
