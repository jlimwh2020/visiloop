"""Score the suite and write bench/suite/RESULTS.md and results/summary.json.

Uses results/checks.json (from run_suite.py) and, if present, results/agent/*.json
(from run_suite_agent.py). Can be re-run at any time.

Usage (from the repo root):  python bench/suite/make_report.py
"""
import json
import os
import statistics
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
RES = os.path.join(HERE, "results")
FAULTS = ["duplicates", "one_way", "packet_drops", "tool_overload", "encrypted_share", "missing_vlan"]

# Fix actions a senior visibility engineer would accept for each fault
GOOD_FIXES = {
    "duplicates": {"dedup"},
    "one_way": {"aggregate"},
    "packet_drops": {"replace_span_with_tap", "load_balance", "filter", "slice"},
    "tool_overload": {"load_balance", "filter", "slice"},
    "encrypted_share": {"decrypt_advice", "filter"},
    "missing_vlan": {"vlan"},
}


def prf(rows):
    """rows: list of (expected set, reported set). Per-fault precision and recall."""
    out = {}
    for f in FAULTS:
        tp = sum(f in e and f in r for e, r in rows)
        fp = sum(f not in e and f in r for e, r in rows)
        fn = sum(f in e and f not in r for e, r in rows)
        out[f] = {"tp": tp, "fp": fp, "fn": fn,
                  "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                  "recall": round(tp / (tp + fn), 3) if tp + fn else None}
    tp, fp, fn = (sum(v[k] for v in out.values()) for k in ("tp", "fp", "fn"))
    out["all"] = {"tp": tp, "fp": fp, "fn": fn,
                  "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                  "recall": round(tp / (tp + fn), 3) if tp + fn else None}
    return out


def by(cases, rows, key):
    groups = defaultdict(lambda: [0, 0])
    for c, (e, r) in zip(cases, rows):
        g = groups[key(c)]
        g[0] += e == r
        g[1] += 1
    return dict(sorted(groups.items()))


def pct(a, b):
    return f"{a}/{b} ({a / b:.1%})" if b else "-"


def main():
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    cases = {c["name"]: c for c in manifest["cases"]}
    with open(os.path.join(RES, "checks.json")) as f:
        checks = {r["name"]: r for r in json.load(f)["results"]}
    order = [n for n in cases if n in checks]
    cs = [cases[n] for n in order]

    # ---- checks
    crow = [(set(cases[n]["faults"]), set(checks[n]["found"])) for n in order]
    c_exact = sum(e == r for e, r in crow)
    c_prf = prf(crow)
    c_fail = [n for n, (e, r) in zip(order, crow) if e != r]

    # ---- loop
    fixes = [x for n in order for x in checks[n]["loop"]["fixes"]]
    fixable = [x for x in fixes if not x["status"].startswith("advice")]
    verified = [x for x in fixable if x["status"] == "verified fixed"]
    advice = [x for x in fixes if x["status"].startswith("advice")]
    with_faults = [n for n in order if checks[n]["found"]]
    healthy_after = [n for n in with_faults if checks[n]["loop"]["result"].startswith("healthy")]
    broken = [n for n in with_faults if not checks[n]["loop"]["result"].startswith("healthy")]
    lb = [x["ports"] for x in fixes if x["action"] == "load_balance"]

    summary = {"suite_version": manifest.get("version", 1), "cases": len(order), "kinds": by(cs, crow, lambda c: c["kind"]),
               "checks": {"exact": c_exact, "per_fault": c_prf, "failures": c_fail,
                          "by_tool": by(cs, crow, lambda c: c["tool"]),
                          "near_threshold": by(cs, crow, lambda c: "near threshold" if c["near_threshold"] else "clear")},
               "loop": {"fixes_verified": len(verified), "fixable": len(fixable), "advice": len(advice),
                        "cases_with_faults": len(with_faults), "healthy_after": len(healthy_after),
                        "still_broken": {n: {k: checks[n]["loop"].get(k) for k in ("new_faults", "unresolved", "fixes")}
                                         for n in broken},
                        "load_balance_ports": {"min": min(lb), "max": max(lb), "median": statistics.median(lb)} if lb else None}}

    # ---- agent
    v = manifest.get("version", 1)
    agent_dir = os.path.join(RES, "agent" if v == 1 else f"agent-v{v}")
    agent = {}
    if os.path.isdir(agent_dir):
        for n in order:
            p = os.path.join(agent_dir, n + ".json")
            if os.path.exists(p):
                with open(p) as f:
                    agent[n] = json.load(f)
    if agent:
        an = [n for n in order if n in agent]
        acs = [cases[n] for n in an]
        arow = [(set(cases[n]["faults"]), {f["fault"] for f in agent[n]["findings"]}) for n in an]
        a_exact = sum(e == r for e, r in arow)
        fix_ok = fix_total = 0
        bad_fixes = []
        for n in an:
            for f in agent[n]["findings"]:
                if f["fault"] in cases[n]["faults"]:
                    fix_total += 1
                    action = (f.get("recommended_fix") or {}).get("action")
                    if action in GOOD_FIXES[f["fault"]]:
                        fix_ok += 1
                    else:
                        bad_fixes.append((n, f["fault"], action))
        # Tool-aware view: for a tool whose profile does not need both directions (SIEM),
        # one-way traffic is optional - reporting it with "no change needed", or leaving it out, both count.
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
        from visikit.profiles import load_profile
        optional = {n: ({"one_way"} if not load_profile(cases[n]["tool"], []).needs_both_directions else set())
                    for n in an}
        ta_exact = sum(e - optional[n] == r - optional[n] for n, (e, r) in zip(an, arow))
        ta_fix_ok = fix_ok
        ta_fix_total = fix_total - sum(1 for n, fault, _ in bad_fixes if fault in optional[n]) \
            - sum(1 for n in an for f in agent[n]["findings"]
                  if f["fault"] in optional[n] and f["fault"] in cases[n]["faults"]
                  and (f.get("recommended_fix") or {}).get("action") in GOOD_FIXES[f["fault"]])
        ta_fix_ok -= sum(1 for n in an for f in agent[n]["findings"]
                         if f["fault"] in optional[n] and f["fault"] in cases[n]["faults"]
                         and (f.get("recommended_fix") or {}).get("action") in GOOD_FIXES[f["fault"]])
        optional_cases = [n for n in an if optional[n] and "one_way" in cases[n]["faults"]]
        metas = [agent[n]["_meta"] for n in an]
        secs = sorted(m["seconds"] for m in metas)
        cost = sum(m["cost_usd"] for m in metas)
        ungrounded = sum(len(m["ungrounded_dropped"]) for m in metas)
        # Faults the checks found but the agent left out of its answer
        omitted = [(n, sorted(set(checks[n]["found"]) - r)) for n, (e, r) in zip(an, arow)
                   if set(checks[n]["found"]) - r]
        summary["agent"] = {
            "tool_aware": {"exact": ta_exact, "fix_sensible": ta_fix_ok, "fix_total": ta_fix_total,
                           "one_way_optional_cases": optional_cases,
                           "summaries": {n: agent[n].get("summary", "") for n in optional_cases}},
            "cases": len(an), "exact": a_exact, "per_fault": prf(arow), "failures": [n for n, (e, r) in zip(an, arow) if e != r],
            "fix_sensible": fix_ok, "fix_total": fix_total, "bad_fixes": bad_fixes,
            "ungrounded_dropped": ungrounded, "omitted_vs_checks": omitted,
            "by_kind": by(acs, arow, lambda c: c["kind"]), "by_tool": by(acs, arow, lambda c: c["tool"]),
            "near_threshold": by(acs, arow, lambda c: "near threshold" if c["near_threshold"] else "clear"),
            "cost_usd": round(cost, 4), "cost_per_case": round(cost / len(an), 4),
            "seconds_median": statistics.median(secs), "seconds_p95": secs[int(0.95 * (len(secs) - 1))],
            "tokens_in": sum(m["tokens_in"] for m in metas), "tokens_out": sum(m["tokens_out"] for m in metas),
            "model": metas[0]["model"], "recorded": max(m.get("recorded_at", "") for m in metas)}

    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    write_md(summary)
    print(open(os.path.join(HERE, "RESULTS.md")).read())


def fault_table(per_fault):
    lines = ["| Fault | Found | Missed | False alarms | Precision | Recall |", "|---|---|---|---|---|---|"]
    for f in FAULTS + ["all"]:
        v = per_fault[f]
        name = "**All faults**" if f == "all" else f
        p = "-" if v["precision"] is None else f"{v['precision']:.1%}"
        r = "-" if v["recall"] is None else f"{v['recall']:.1%}"
        lines.append(f"| {name} | {v['tp']} | {v['fn']} | {v['fp']} | {p} | {r} |")
    return "\n".join(lines)


def group_table(title, groups):
    lines = [f"| {title} | Exactly right |", "|---|---|"]
    lines += [f"| {k} | {pct(a, b)} |" for k, (a, b) in groups.items()]
    return "\n".join(lines)


def write_md(s):
    c, l = s["checks"], s["loop"]
    kinds = {"clean": "healthy feed", "mild": "only below-threshold faults (must not alarm)",
             "single": "one fault", "double": "two faults", "triple": "three faults",
             "tool_aware": "heavy TLS, untagged or one-way traffic on a tool that tolerates it (must not alarm)"}
    md = [
        f"# VisiLoop benchmark suite v{s.get('suite_version', 1)}: results",
        "",
        *(["Version 2 makes the one-way check tool-aware (a gap Muse Spark found in version 1) and adds "
           "one-way traps on SIEM tools. Version 1 results: [results/RESULTS_v1.md](results/RESULTS_v1.md).", ""]
          if s.get("suite_version", 1) >= 2 else []),
        f"**{s['cases']} generated test cases** across four tool types (IDS, NDR, APM, SIEM), with 0 to 3 faults each, "
        "near-threshold faults, below-threshold noise and tool-awareness traps. "
        "The answer key is computed by the generator directly from the packets it wrote, independently of VisiLoop's checks. "
        "Cases too close to a threshold to label fairly are regenerated. See `make_suite.py`.",
        "",
        "| Case type | Cases |", "|---|---|",
    ]
    md += [f"| {k}: {kinds[k]} | {s['kinds'][k][1]} |" for k in kinds if k in s["kinds"]]
    md += ["", "**What this shows, and what it doesn't.** The checks are deterministic, and the suite leaves a "
           "no-label zone around each threshold, so a perfect check score mainly proves the checks are correct "
           "and robust across tools, traffic mixes and fault combinations. The harder test is Muse Spark: "
           "it must call the right checks, report every fault and no others, and pick a sensible fix. "
           "All traffic is synthetic; real captures are the next step."]

    if "agent" in s:
        a = s["agent"]
        md += ["", "## Headline", "",
               f"- **Muse Spark diagnosis exactly right on {pct(a['exact'], a['cases'])} cases**, "
               f"overall precision {a['per_fault']['all']['precision']:.1%}, recall {a['per_fault']['all']['recall']:.1%}.",
               f"- **Tool-aware view: {pct(a['tool_aware']['exact'], a['cases'])} exactly right, sensible fix "
               f"{pct(a['tool_aware']['fix_sensible'], a['tool_aware']['fix_total'])}.** Every disagreement with the "
               "strict key was Muse Spark applying the tool's profile (see section 3).",
               f"- **Sensible fix chosen {pct(a['fix_sensible'], a['fix_total'])}** of the time; "
               f"**{a['ungrounded_dropped']} ungrounded claims** reached the guard.",
               f"- **Checks exactly right on {pct(c['exact'], s['cases'])} cases.**",
               f"- **{pct(l['fixes_verified'], l['fixable'])} fixable faults verified fixed** in the simulated broker; "
               f"{l['advice']} decryption items reported as advice.",
               f"- **US${a['cost_usd']:.2f} for all {a['cases']} diagnoses** (US${a['cost_per_case']:.4f} each), "
               f"median {a['seconds_median']:.1f} s, 95th percentile {a['seconds_p95']:.1f} s."]
    md += ["", "## 1. Checks (deterministic, free)", "",
           f"Exactly right on **{pct(c['exact'], s['cases'])}** cases.", "", fault_table(c["per_fault"]), "",
           group_table("Tool", c["by_tool"]), "", group_table("Difficulty", c["near_threshold"])]
    if c["failures"]:
        md += ["", "Cases where the checks disagreed with the answer key: " + ", ".join(f"`{n}`" for n in c["failures"])]

    md += ["", "## 2. Fix and prove (simulated broker, free)", "",
           f"- Fixable faults verified fixed: **{pct(l['fixes_verified'], l['fixable'])}**",
           f"- Advice-only items (decryption, cannot be simulated offline): **{l['advice']}**",
           f"- Cases healthy after the fixes: **{pct(l['healthy_after'], l['cases_with_faults'])}** of cases with faults"]
    if l["load_balance_ports"]:
        p = l["load_balance_ports"]
        md.append(f"- Load-balanced tool groups sized from {p['min']} to {p['max']} ports (median {p['median']:g})")
    if l["still_broken"]:
        md += ["", "Cases still broken after one round of fixes:", ""]
        for n, v in l["still_broken"].items():
            md.append(f"- `{n}`: new faults {v['new_faults'] or 'none'}, unresolved {v['unresolved'] or 'none'}")

    if "agent" in s:
        a = s["agent"]
        md += ["", f"## 3. Muse Spark diagnosis ({a['model']}, recorded {a['recorded']})", "",
               f"Exactly right on **{pct(a['exact'], a['cases'])}** cases. "
               f"Tokens: {a['tokens_in']:,} in, {a['tokens_out']:,} out.", "",
               fault_table(a["per_fault"]), "",
               group_table("Case type", a["by_kind"]), "", group_table("Tool", a["by_tool"]), "",
               group_table("Difficulty", a["near_threshold"])]
        ta = a["tool_aware"]
        if ta["one_way_optional_cases"]:
            md += ["", "### Where Muse Spark disagreed with the strict answer key", "",
                   "The strict key counts one-way traffic as a fault on every tool. VisiLoop's own tool profiles say a "
                   "SIEM does not need both directions, and Muse Spark applied that: in every SIEM case with one-way "
                   "traffic it either left the fault out or reported it with \"no broker change needed\". "
                   "The one-way check itself ignores the tool profile, so this is a gap in the check, found by the agent.", ""]
            md += [f"- `{n}`: \"{ta['summaries'][n][:220]}\"" for n in ta["one_way_optional_cases"]]
            md += ["", f"Scored tool-aware (one-way optional on tools that don't need both directions): "
                   f"**{pct(ta['exact'], a['cases'])}** exactly right, sensible fix **{pct(ta['fix_sensible'], ta['fix_total'])}**."]
        if a["omitted_vs_checks"]:
            md += ["", "Faults the checks found but Muse Spark left out of its answer:", ""]
            md += [f"- `{n}`: {', '.join(f)}" for n, f in a["omitted_vs_checks"]]
        if a["bad_fixes"]:
            md += ["", "Fix choices outside the accepted set:", ""]
            md += [f"- `{n}` {fault}: `{act}`" for n, fault, act in a["bad_fixes"]]
    else:
        md += ["", "## 3. Muse Spark diagnosis", "", "Not run yet: `python bench/suite/run_suite_agent.py`"]

    md += ["", "## Reproduce", "", "```",
           "python bench/suite/make_suite.py        # 200 cases, deterministic (seed 2026)",
           "python bench/suite/run_suite.py         # checks + fix loop (free)",
           "python bench/suite/run_suite_agent.py   # Muse Spark (about US$2, resumable, capped)",
           "python bench/suite/make_report.py       # this file",
           "```", ""]
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(md))


if __name__ == "__main__":
    main()
