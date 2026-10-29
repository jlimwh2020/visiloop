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

from visikit.core.registry import applicable, load_plugins
from visikit.core.schema import FeedContext
from visikit.profiles import load_profile


PER_PORT = {"tool_overload"}    # capacity is judged per tool port; everything else on the whole tool group
MAX_ROUNDS = 3


def check_all(ctx, only=None, skip=()):
    detectors, _ = load_plugins()
    return [f for name, cls in detectors.items() if (only is None or name in only) and name not in skip
            and applicable(cls, ctx) for f in cls().run(ctx)]


def _plan(ctx, findings, workdir):
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
    return planned


def _simulate(planned, ctx, pcaps, workdir):
    """Apply fixes in pipeline order. Returns (tool-port captures, the stream before any split, advice faults)."""
    group, advice = None, []
    for plugin, fx in planned:
        if plugin.action == "load_balance":
            group = list(pcaps)
        result = plugin.simulate(pcaps, ctx, fx, workdir)
        if result is None:
            advice.append(fx.fault)
        else:
            pcaps = result
    return pcaps, group or list(pcaps), advice


def _check_after(ctx, pcaps, group):
    """Re-check the result. With a load-balanced tool group, port capacity is checked per port and
    everything else (traffic mix, directions, duplicates...) on the group as a whole, because hashing
    whole flows to ports makes each port's mix differ a little from the group's."""
    if len(pcaps) == 1:
        return {ctx.feed: check_all(replace(ctx, pcap=pcaps[0], ingress=None))}
    after = {}
    for i, p in enumerate(pcaps):
        after[f"{ctx.feed}-port{i + 1}"] = check_all(replace(ctx, feed=f"{ctx.feed}-port{i + 1}", pcap=p, ingress=None),
                                                     only=PER_PORT)
    for j, g in enumerate(group):
        name = f"{ctx.feed}-group" if len(group) == 1 else f"{ctx.feed}-group{j + 1}"
        after[name] = check_all(replace(ctx, feed=name, pcap=g, ingress=None), skip=PER_PORT)
    return after


def remediate(ctx, findings, workdir):
    """Plan, simulate and verify fixes. If a fix reveals a new fault (turning slicing off brings back
    jumbo frames; aggregating both directions doubles the load), plan a further round, up to MAX_ROUNDS."""
    before = {f.fault for f in findings}
    pcaps, group = [ctx.pcap], [ctx.pcap]
    planned_all, advice_all, attempted = [], [], set()
    lb = None
    cur_ctx, cur_findings = ctx, findings
    rounds = 0
    revealed = []
    for rnd in range(1, MAX_ROUNDS + 1):
        rounds = rnd
        rd = os.path.join(workdir, f"round{rnd}")
        os.makedirs(rd, exist_ok=True)
        planned = _plan(cur_ctx, cur_findings, rd)
        attempted |= {fx.fault for _, fx in planned}
        planned_all += [(pl, fx, rnd) for pl, fx in planned]
        run = list(planned)
        if lb and not any(pl.action == "load_balance" for pl, _ in run):
            run.append(lb)                              # keep the tool group sized in an earlier round
        start = pcaps if rnd == 1 else group
        pcaps, group, advice = _simulate(run, cur_ctx, start, rd)
        lb = next(((pl, fx) for pl, fx in planned if pl.action == "load_balance"), lb)
        advice_all += advice
        after = _check_after(ctx, pcaps, group)
        remaining = {f.fault for fs in after.values() for f in fs}
        to_fix = remaining - set(advice_all) - attempted
        if not to_fix or rnd == MAX_ROUNDS:
            break
        # A fix revealed something new: diagnose it on the repaired stream and go round again
        cur_findings, seen = [], set()
        for fs in after.values():
            for f in fs:
                if f.fault in to_fix and f.fault not in seen:
                    cur_findings.append(f)
                    seen.add(f.fault)
        revealed += sorted(seen)
        cur_ctx = replace(ctx, pcap=group[0] if len(group) == 1 else pcaps[0], ingress=None)

    fix_reports = []
    for plugin, fx, rnd in planned_all:
        if fx.fault in advice_all:
            status = "advice (cannot be verified offline)"
        elif fx.fault in remaining:
            status = "not fixed"
        else:
            status = "verified fixed"
        fix_reports.append({**fx.to_dict(), "status": status, "round": rnd})

    from visikit.core.tools import data_bytes
    bytes_before = data_bytes(ctx.pcap) if ctx.pcap else 0
    bytes_after = sum(data_bytes(p) for p in pcaps if p)
    advice_set = set(advice_all)
    new_faults = sorted(remaining - before - advice_set)
    unresolved = sorted((remaining & before) - advice_set)
    healthy = not new_faults and not unresolved
    return {
        "before": [f.to_dict() for f in findings],
        "fixes": fix_reports,
        "after": {port: [f.to_dict() for f in fs] for port, fs in after.items()},
        "tool_ports_after": len(pcaps),
        "after_pcaps": pcaps,
        "bytes_before": bytes_before,
        "bytes_after": bytes_after,
        "rounds": rounds,
        "revealed": revealed,
        "new_faults": new_faults,
        "unresolved": unresolved,
        "advice_only": sorted(advice_set),
        "result": ("healthy" if not advice_set else "healthy except advice items") if healthy else "still broken",
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
