"""Muse Spark diagnosis agent.

The agent gets every registered VisiKit detector as a tool, runs the checks it
needs, and returns a structured diagnosis: root cause, impact on the tool and a
recommended packet broker fix for each fault.

Usage (from the repo root):
    python -m visikit.agent.diagnose bench/cases/one_way.pcap --tool IDS
"""
import argparse
import json
import os
import re
import time

from visikit.core.registry import applicable, load_plugins
from visikit.core.schema import FeedContext
from visikit.profiles import load_profile

MODEL = os.environ.get("VISILOOP_MODEL", "muse-spark-1.2")
BASE_URL = "https://api.meta.ai/v1"
PRICE_IN, PRICE_OUT = 1.25 / 1e6, 4.25 / 1e6       # US$ per token (muse-spark)
MAX_TURNS = 6

FIX_ACTIONS = ["dedup", "aggregate", "replace_span_with_tap", "load_balance", "filter", "slice", "vlan", "decrypt_advice",
               "disable_slicing", "strip_tunnel", "mtu_advice", "check_link", "tool_capacity", "upgrade_port", "none"]

SYSTEM = (
    "You are VisiLoop, a network visibility assistant used by the network owner's own "
    "security and network engineers. Your job is defensive: make sure their security "
    "monitoring tools (NDR, IDS, APM, SIEM) receive complete, correct traffic, and "
    "recommend fixes on TAPs and packet brokers to improve detection coverage. All "
    "captures come from the engineer's own, authorised environment.\n\n"
    "Rules:\n"
    "- Base every finding on a check result. Never report a fault that no check returned.\n"
    "- Call the checks you need (calling all of them is fine), then answer.\n"
    "- Explain the most likely root cause in plain English, as a senior visibility engineer would.\n"
    f"- recommended_fix.action must be one of: {', '.join(FIX_ACTIONS)}.\n"
    "- Final answer: ONLY a JSON object, no other text, in this shape:\n"
    '{"feed": str, "status": "healthy" | "degraded", "summary": str, '
    '"findings": [{"fault": str, "severity": "low"|"medium"|"high", "root_cause": str, '
    '"impact_on_tool": str, "recommended_fix": {"action": str, "params": object, "why": str}, '
    '"evidence_frames": [int]}]}'
)


def _tool_specs(detectors):
    specs = [{
        "type": "function",
        "function": {
            "name": f"check_{name}",
            "description": (cls.__doc__ or name).strip().split("\n\n")[0].replace("\n", " "),
            "parameters": {"type": "object", "properties": {}},
        },
    } for name, cls in sorted(detectors.items())]
    specs.append({
        "type": "function",
        "function": {
            "name": "get_tool_profile",
            "description": "What the monitoring tool on this feed needs: directions, payload, port speed, VLANs, encryption tolerance, largest frame.",
            "parameters": {"type": "object", "properties": {}},
        },
    })
    return specs


def _parse_json(text):
    text = (text or "").strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("model did not return JSON")
    return json.loads(text[start:end + 1])


def make_client():
    from openai import OpenAI
    return OpenAI(base_url=BASE_URL, api_key=os.environ["MODEL_API_KEY"])


def diagnose(ctx: FeedContext, client=None, model: str = MODEL, verbose: bool = False) -> dict:
    """Run the agent on one feed. Returns the diagnosis dict plus a `_meta` block."""
    detectors, _ = load_plugins()
    detectors = {k: v for k, v in detectors.items() if applicable(v, ctx)}
    client = client or make_client()
    check_results = {}                      # fault -> list of finding dicts (ground truth for the guard)

    def call_tool(name):
        if name == "get_tool_profile":
            p = ctx.profile
            return {"tool_type": p.tool_type, "needs_both_directions": p.needs_both_directions,
                    "needs_full_payload": p.needs_full_payload, "port_speed_gbps": p.max_rate_gbps,
                    "required_vlans": p.required_vlans, "max_encrypted_share": p.max_encrypted_share,
                    "max_frame_bytes": p.max_frame_bytes}
        fault = name.removeprefix("check_")
        if fault not in detectors:
            return {"error": f"unknown check {name}"}
        found = [f.to_dict() for f in detectors[fault]().run(ctx)]
        check_results[fault] = found
        for f in found:
            f.pop("explanation", None)
        return {"fault": fault, "result": "fault found" if found else "healthy", "findings": found}

    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"Feed '{ctx.feed}' delivers traffic to a {ctx.profile.tool_type}. "
            "Check whether this tool receives complete, correct traffic, and recommend "
            "packet broker changes to improve its detection coverage.")},
    ]
    usage_in = usage_out = 0
    started = time.time()
    for turn in range(MAX_TURNS):
        resp = client.chat.completions.create(
            model=model, messages=messages, tools=_tool_specs(detectors), temperature=0.2)
        if getattr(resp, "usage", None):
            usage_in += resp.usage.prompt_tokens or 0
            usage_out += resp.usage.completion_tokens or 0
        msg = resp.choices[0].message
        calls = getattr(msg, "tool_calls", None) or []
        if not calls and not check_results:
            # The model answered without checking: run every check ourselves and ask again
            results = {name: call_tool(f"check_{name}") for name in sorted(detectors)}
            results["tool_profile"] = call_tool("get_tool_profile")
            if verbose:
                print("  model skipped the tools; ran all checks and re-asked")
            messages.append({"role": "assistant", "content": msg.content or ""})
            messages.append({"role": "user", "content": (
                "Here are the results of every check on this feed. Base your diagnosis only on them "
                "and reply with the JSON object.\n" + json.dumps(results))})
            continue
        if not calls:
            break
        messages.append({"role": "assistant", "content": msg.content or "",
                         "tool_calls": [{"id": c.id, "type": "function",
                                         "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"}}
                                        for c in calls]})
        for c in calls:
            result = call_tool(c.function.name)
            if verbose:
                print(f"  tool: {c.function.name} -> {result.get('result', result.get('error', 'ok'))}")
            messages.append({"role": "tool", "tool_call_id": c.id, "content": json.dumps(result)})
    else:
        raise RuntimeError("agent did not finish within the turn limit")

    diagnosis = _parse_json(msg.content)

    # Grounding guard: drop any finding no check actually returned
    grounded, dropped = [], []
    confirmed = {fault for fault, found in check_results.items() if found}
    for f in diagnosis.get("findings", []):
        (grounded if f.get("fault") in confirmed else dropped).append(f)
    diagnosis["findings"] = grounded
    diagnosis["status"] = "degraded" if grounded else "healthy"
    diagnosis["_meta"] = {
        "model": model, "checks_called": sorted(check_results), "ungrounded_dropped": dropped,
        "tokens_in": usage_in, "tokens_out": usage_out,
        "cost_usd": round(usage_in * PRICE_IN + usage_out * PRICE_OUT, 5),
        "seconds": round(time.time() - started, 1),
    }
    return diagnosis


def main():
    ap = argparse.ArgumentParser(description="Diagnose one monitoring feed with Muse Spark")
    ap.add_argument("pcap")
    ap.add_argument("--tool", default="IDS", help="NDR, IDS, APM or SIEM")
    ap.add_argument("--vlans", default="10,20", help="required VLANs, comma-separated")
    ap.add_argument("--feed", default="feed-1")
    a = ap.parse_args()
    vlans = [int(v) for v in a.vlans.split(",") if v]
    ctx = FeedContext(a.feed, a.pcap, load_profile(a.tool, vlans))
    result = diagnose(ctx, verbose=True)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
