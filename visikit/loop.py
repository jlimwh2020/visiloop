"""VisiLoop's closed loop: diagnose -> fix -> prove.

1. Diagnose: run every detector (and optionally the Muse Spark agent for explanations).
2. Fix: each fault's fix plug-in calculates its settings from the measurements.
3. Prove: a simulated broker applies the fixes in order and every resulting tool
   port is re-checked. A fault counts as fixed only if no check finds it afterwards.

Usage (from the repo root):
    python -m visikit.loop bench/cases/one_way.pcap --ingress bench/cases/clean.pcap --tool IDS
    python -m visikit.loop ... --agent        # add Muse Spark explanations
"""
import argparse
import inspect
import json
import os
import tempfile
from dataclasses import replace

from visikit.core.registry import load_plugins
from visikit.core.schema import FeedContext
from visikit.profiles import load_profile


def check_all(ctx):
    detectors, _ = load_plugins()
    return [f for cls in detectors.values() for f in cls().run(ctx)]


def remediate(ctx, findings, workdir):
    """Plan, simulate and verify fixes for the given findings."""
    _, fixes = load_plugins()
    planned = []
    for finding in findings:
        cls = fixes.get(finding.fault)
        if not cls:
            continue
        plugin = cls()
        kwargs = {"workdir": workdir} if "workdir" in inspect.signature(plugin.config).parameters else {}
        planned.append((plugin, plugin.config(ctx, finding, **kwargs)))
    planned.sort(key=lambda pf: pf[0].stage)

    pcaps, advice_only = [ctx.pcap], []
    for plugin, fx in planned:
        result = plugin.simulate(pcaps, ctx, fx, workdir)
        if result is None:
            advice_only.append(fx.fault)
        else:
            pcaps = result

    after = {}
    for i, p in enumerate(pcaps):
        port = ctx.feed if len(pcaps) == 1 else f"{ctx.feed}-port{i + 1}"
        after[port] = check_all(replace(ctx, feed=port, pcap=p, ingress=None))
    remaining = {f.fault for fs in after.values() for f in fs}
    before = {f.fault for f in findings}

    fix_reports = []
    for plugin, fx in planned:
        if fx.fault in advice_only:
            status = "advice (cannot be verified offline)"
        elif fx.fault in remaining:
            status = "not fixed"
        else:
            status = "verified fixed"
        fix_reports.append({**fx.to_dict(), "status": status})

    from visikit.core.tools import data_bytes
    bytes_before, bytes_after = data_bytes(ctx.pcap), sum(data_bytes(p) for p in pcaps)
    new_faults = sorted(remaining - before)
    unresolved = sorted((remaining & before) - set(advice_only))
    healthy = not new_faults and not unresolved
    return {
        "before": [f.to_dict() for f in findings],
        "fixes": fix_reports,
        "after": {port: [f.to_dict() for f in fs] for port, fs in after.items()},
        "tool_ports_after": len(pcaps),
        "after_pcaps": pcaps,
        "bytes_before": bytes_before,
        "bytes_after": bytes_after,
        "new_faults": new_faults,
        "unresolved": unresolved,
        "advice_only": sorted(advice_only),
        "result": ("healthy" if not advice_only else "healthy except advice items") if healthy else "still broken",
    }


def run_loop(ctx, use_agent=False, client=None, workdir=None, diagnosis=None):
    """diagnosis: optional recorded Muse Spark diagnosis to use instead of calling the model."""
    findings = check_all(ctx)
    if use_agent and findings and diagnosis is None:
        from visikit.agent.diagnose import diagnose
        diagnosis = diagnose(ctx, client=client)
    own_tmp = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="visiloop_")
    report = remediate(ctx, findings, workdir) if findings else {
        "before": [], "fixes": [], "after": {}, "tool_ports_after": 1, "new_faults": [],
        "unresolved": [], "advice_only": [], "result": "healthy (no faults found)"}
    if diagnosis:
        by_fault = {f["fault"]: f for f in diagnosis["findings"]}
        for fx in report["fixes"]:
            a = by_fault.get(fx["fault"], {})
            fx["root_cause"] = a.get("root_cause", "")
            fx["why"] = a.get("recommended_fix", {}).get("why", "")
            fx["agent_action"] = a.get("recommended_fix", {}).get("action")
        report["summary"] = diagnosis.get("summary", "")
        report["agent_meta"] = diagnosis["_meta"]
        report["diagnosis"] = diagnosis
    report["workdir"] = workdir if not own_tmp else None
    return report


def main():
    ap = argparse.ArgumentParser(description="Diagnose, fix and prove one monitoring feed")
    ap.add_argument("pcap")
    ap.add_argument("--ingress", help="lossless capture of what the broker receives (needed to verify some fixes)")
    ap.add_argument("--tool", default="IDS")
    ap.add_argument("--vlans", default="10,20")
    ap.add_argument("--feed", default="feed-1")
    ap.add_argument("--agent", action="store_true", help="add Muse Spark explanations (uses API credits)")
    a = ap.parse_args()
    ctx = FeedContext(a.feed, a.pcap, load_profile(a.tool, [int(v) for v in a.vlans.split(",") if v]), a.ingress)
    print(json.dumps(run_loop(ctx, use_agent=a.agent), indent=2))


if __name__ == "__main__":
    main()
