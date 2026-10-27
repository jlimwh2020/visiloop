"""VisiLoop dashboard: See -> Diagnose -> Fix -> Prove.

Run from the repo root:
    python -m streamlit run ui/app.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import streamlit as st                                            # noqa: E402

from visikit.core.registry import load_plugins                    # noqa: E402
from visikit.core.schema import FeedContext                       # noqa: E402
from visikit.loop import run_loop                                 # noqa: E402
from visikit.profiles import load_profile                         # noqa: E402
from visikit.proof import ids                                     # noqa: E402
from visikit.vision import diagram as dg                          # noqa: E402

CASES = os.path.join(ROOT, "bench", "cases")
DEMO_DIAGRAM = os.path.join(ROOT, "demo", "diagram.png")
TMP = os.path.join(tempfile.gettempdir(), "visiloop_ui")
os.makedirs(TMP, exist_ok=True)

NICE = {
    "duplicates": "Duplicates", "one_way": "One-way traffic", "packet_drops": "Packet drops",
    "tool_overload": "Tool overload", "encrypted_share": "Encrypted share", "missing_vlan": "Missing VLANs",
}
ACTION_NICE = {
    "dedup": "Enable deduplication", "aggregate": "Aggregate both TAP legs",
    "replace_span_with_tap": "Replace SPAN with a passive TAP", "load_balance": "Load balance across tool ports",
    "vlan": "Preserve VLAN tags", "decrypt_advice": "Add a decryption point",
}

st.set_page_config(page_title="VisiLoop", page_icon="🔁", layout="wide")


def _save_upload(upload, name):
    path = os.path.join(TMP, name)
    with open(path, "wb") as f:
        f.write(upload.getbuffer())
    return path


@st.cache_data(show_spinner=False)
def ids_available():
    return ids.available()


@st.cache_data(show_spinner=False)
def prove_cached(before_pcap, after_pcaps):
    return ids.prove_detection(before_pcap, list(after_pcaps))


@st.cache_data(show_spinner=False)
def run_cached(pcap, ingress, tool, vlans, use_agent, _mtime):
    ctx = FeedContext("feed-1", pcap, load_profile(tool, list(vlans)), ingress)
    return run_loop(ctx, use_agent=use_agent, workdir=tempfile.mkdtemp(dir=TMP))


# ---------------- sidebar ----------------
st.sidebar.title("VisiLoop")
st.sidebar.caption("Your security tools may be blind. VisiLoop finds out why, fixes it, and proves it.")

source = st.sidebar.radio("Traffic capture", ["Demo case", "Upload my own"], horizontal=True)
pcap = ingress = None
if source == "Demo case":
    if not os.path.exists(os.path.join(CASES, "manifest.json")):
        st.sidebar.error("No demo cases yet. Run: python bench/inject.py")
    else:
        manifest = json.load(open(os.path.join(CASES, "manifest.json")))
        cases = {c["name"]: c for c in manifest["cases"]}
        default = "breach" if "breach" in cases else ("combined" if "combined" in cases else list(cases)[0])
        pick = st.sidebar.selectbox("Case", list(cases), index=list(cases).index(default))
        pcap = os.path.join(CASES, cases[pick]["file"])
        ingress = os.path.join(CASES, cases[pick]["ingress"])
else:
    up = st.sidebar.file_uploader("Capture from the tool's input (.pcap)", type=["pcap", "pcapng"])
    up_in = st.sidebar.file_uploader("Optional: broker ingress capture, to prove fixes", type=["pcap", "pcapng"])
    if up:
        pcap = _save_upload(up, "feed_" + up.name)
    if up_in:
        ingress = _save_upload(up_in, "ingress_" + up_in.name)

tool = st.sidebar.selectbox("Tool on this feed", ["IDS", "NDR", "APM", "SIEM"])
vlans = tuple(int(v) for v in st.sidebar.text_input("Required VLANs", "10,20").split(",") if v.strip())

dsrc = st.sidebar.radio("Network diagram", ["Demo diagram", "Upload", "None"], horizontal=True)
diagram = DEMO_DIAGRAM if dsrc == "Demo diagram" else None
if dsrc == "Upload":
    upd = st.sidebar.file_uploader("Diagram image (.png/.jpg)", type=["png", "jpg", "jpeg"])
    if upd:
        diagram = _save_upload(upd, "diagram_" + upd.name)

use_agent = st.sidebar.checkbox("Explain with Muse Spark (about US$0.01)", value=True)
use_ids = st.sidebar.checkbox("Detection proof with Suricata", value=True,
                              help="Runs Suricata with a harmless test signature on the feed before and after the fix")
go = st.sidebar.button("Run VisiLoop", type="primary", width="stretch", disabled=pcap is None)

# ---------------- main ----------------
st.title("🔁 VisiLoop")
st.markdown("**See → Diagnose → Fix → Prove.** Checks whether a security tool receives complete, correct "
            "traffic, writes a vendor-neutral packet broker fix, and proves it works in a simulated broker.")

if go:
    st.session_state["args"] = (pcap, ingress, tool, vlans, use_agent, diagram, use_ids)
args = st.session_state.get("args")
if not args:
    st.info("Choose a capture and a diagram in the sidebar, then click **Run VisiLoop**.")
    st.stop()
pcap, ingress, tool, vlans, use_agent, diagram, use_ids = args

with st.spinner("Checking the feed, planning fixes and proving them..."):
    try:
        report = run_cached(pcap, ingress, tool, vlans, use_agent and bool(os.environ.get("MODEL_API_KEY")),
                            os.path.getmtime(pcap))
    except Exception as e:
        st.error(f"VisiLoop could not finish: {e}")
        st.stop()
if use_agent and not os.environ.get("MODEL_API_KEY"):
    st.warning("MODEL_API_KEY is not set, so Muse Spark explanations were skipped.")

inv = None
if diagram:
    with st.spinner("Reading the network diagram (SAM 3.1 + Muse Spark, cached after the first read)..."):
        try:
            inv = dg.load_or_read(diagram)
        except Exception as e:
            st.warning(f"Diagram could not be read: {e}")

before = report["before"]
faults_before = {f["fault"] for f in before}

# ---- 1. See ----
st.header("1 · See")
if inv:
    c1, c2 = st.columns([3, 2])
    with c1:
        st.image(diagram, caption="Customer network diagram", width="stretch")
    with c2:
        st.metric("Devices found by SAM 3.1", len(inv["boxes"]))
        st.markdown("**Capture points read by Muse Spark**")
        labels = {d["box"]: d["label"] for d in inv["devices"]}
        st.dataframe([{"Capture point": labels.get(c["box"], c["box"]), "Type": c.get("kind", "").upper(),
                       "Mirrors": c.get("direction", "")} for c in inv["capture_points"]],
                     hide_index=True, width="stretch")
else:
    st.caption("No diagram selected; findings will be shown without one.")

# ---- 2. Diagnose ----
st.header("2 · Diagnose")
detectors, _ = load_plugins()
cols = st.columns(len(detectors))
by_fault = {f["fault"]: f for f in before}
for col, name in zip(cols, sorted(detectors)):
    f = by_fault.get(name)
    with col:
        if f:
            st.error(f"**{NICE.get(name, name)}**\n\n{f['metric']:.1%} (limit {f['threshold']:.0%})")
        else:
            st.success(f"**{NICE.get(name, name)}**\n\nhealthy")

if not before:
    st.success(f"This {tool} receives complete, correct traffic. Nothing to fix.")
    st.stop()

if report.get("summary"):
    st.info(f"**Muse Spark:** {report['summary']}")

pins = dg.pin_findings(inv, before, tool) if inv else []
c1, c2 = st.columns([3, 2])
with c1:
    if inv:
        st.image(dg.render(diagram, inv, pins, title="Before: where the faults are"), width="stretch")
with c2:
    for f in before:
        with st.expander(f"🔴 {NICE.get(f['fault'], f['fault'])}: {f['severity']}", expanded=True):
            st.write(f["detail"])
            fx = next((x for x in report["fixes"] if x["fault"] == f["fault"]), {})
            if fx.get("root_cause"):
                st.markdown(f"**Likely root cause (Muse Spark):** {fx['root_cause']}")
            pin = next((p for p in pins if p["fault"] == f["fault"]), None)
            if pin:
                st.markdown(f"**On the diagram:** {pin['reason']}")
            if f.get("evidence"):
                st.caption(f"Evidence: packets {', '.join(map(str, f['evidence'][:10]))}")

# ---- 3. Fix ----
st.header("3 · Fix")
st.caption("Settings are calculated from the measurements. Vendor-neutral, to apply on any packet broker after review.")
for fx in report["fixes"]:
    with st.container(border=True):
        st.subheader(ACTION_NICE.get(fx["action"], fx["action"]))
        if fx.get("why"):
            st.markdown(f"**Why (Muse Spark):** {fx['why']}")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Calculated settings**")
            st.json(fx["params"], expanded=True)
        with c2:
            st.markdown("**Broker configuration (vendor-neutral)**")
            st.json(fx["broker_config"], expanded=True)

# ---- 4. Prove ----
st.header("4 · Prove")
status_icon = {"verified fixed": "✅", "advice (cannot be verified offline)": "🟠", "not fixed": "❌"}
c1, c2 = st.columns([3, 2])
with c1:
    if inv:
        fix_status = {x["fault"]: x["status"] for x in report["fixes"]}
        after_pins = [{**p, "status": fix_status.get(p["fault"], "not fixed")} for p in pins]
        st.image(dg.render(diagram, inv, after_pins, title="After: fixes applied in the simulated broker"),
                 width="stretch")
with c2:
    for fx in report["fixes"]:
        st.markdown(f"{status_icon.get(fx['status'], '')} **{ACTION_NICE.get(fx['action'], fx['action'])}**: {fx['status']}")
    result = report["result"]
    if result == "healthy":
        st.success(f"Every fault is fixed. The {tool} now receives complete, correct traffic.")
    elif result.startswith("healthy except"):
        st.warning("All simulated faults are fixed. Remaining items are advice that needs the customer's "
                   "decryption setup to verify.")
    else:
        st.error("Some faults remain after the fixes. Review the details below.")
    st.markdown(f"**Tool ports after the fix:** {report['tool_ports_after']}")
    if report.get("bytes_before") and report.get("bytes_after"):
        b0, b1 = report["bytes_before"], report["bytes_after"]
        change = (b1 - b0) / b0
        st.metric("Traffic delivered to the tool", f"{b1 / 1e6:.2f} MB", f"{change:+.1%} vs before",
                  delta_color="off")
        if "dedup" in [x["action"] for x in report["fixes"]] and change < 0:
            st.caption("Less traffic from removing duplicate copies: lower load and, for tools licensed by "
                       "volume, lower licence use.")
        elif change > 0:
            st.caption("More traffic because the tool now receives what it was missing (e.g. the second "
                       "direction or dropped packets).")
    after_rows = [{"Tool port": port, "Faults found": ", ".join(NICE.get(f["fault"], f["fault"]) for f in fs) or "none"}
                  for port, fs in report["after"].items()]
    st.dataframe(after_rows, hide_index=True, width="stretch")

if use_ids and report.get("after_pcaps"):
    st.subheader("Detection proof (Suricata)")
    if not ids_available():
        st.caption("Suricata not found. On Windows, install it in WSL Ubuntu: sudo apt install suricata")
    else:
        with st.spinner("Running Suricata on the feed before and after the fix..."):
            try:
                proof = prove_cached(pcap, tuple(report["after_pcaps"]))
            except Exception as e:
                proof = None
                st.warning(f"Suricata could not run: {e}")
        if proof:
            c1, c2, c3 = st.columns([1, 1, 2])
            c1.metric("IDS alerts on the broken feed", proof["before"])
            c2.metric("IDS alerts after VisiLoop's fix", proof["after"], proof["after"] - proof["before"])
            with c3:
                if proof["after"] > proof["before"]:
                    st.success(f"The {tool} was blind to {proof['after'] - proof['before']} alert(s) until the feed was fixed.")
                elif proof["after"] == proof["before"] == 0:
                    st.caption("No test signatures in this capture, so no alerts before or after.")
                for a in proof["after_alerts"][:5]:
                    st.markdown(f"🚨 **{a['signature']}**  \n`{a['src']} → {a['dst']}`")
            st.caption("Uses a harmless test signature (visikit/proof/visiloop.rules) that matches only VisiLoop's "
                       "synthetic test traffic.")

if report.get("agent_meta"):
    m = report["agent_meta"]
    st.caption(f"Muse Spark ({m['model']}): {m['tokens_in']} tokens in, {m['tokens_out']} out, "
               f"US${m['cost_usd']:.4f}, {m['seconds']} s")
