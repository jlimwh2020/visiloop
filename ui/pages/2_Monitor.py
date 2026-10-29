"""VisiLoop continuous monitoring: feed status, history and alerts (reads the monitor's SQLite database)."""
import os
import sqlite3
import sys

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO_DB = os.path.join(ROOT, "demo", "monitor_demo.db")

st.set_page_config(page_title="VisiLoop monitor", page_icon="📈", layout="wide")
st.title("📈 VisiLoop monitor")

db_path = os.environ.get("VISILOOP_MONITOR_DB") or (os.path.join(ROOT, "monitor.db") if os.path.exists(os.path.join(ROOT, "monitor.db")) else DEMO_DB)
if db_path == DEMO_DB:
    st.caption("Showing a simulated morning on the demo IDS feed: a backup window overloads the SPAN destination, "
               "then an optic into the broker starts failing and is replaced. Run your own with "
               "`python -m visikit.monitor --config my_monitor.yaml`.")
if not os.path.exists(db_path):
    st.info("No monitoring data yet. Start the monitor: `python -m visikit.monitor --config demo/monitor.yaml --fast`")
    st.stop()

con = sqlite3.connect(db_path)
cycles = pd.read_sql("SELECT * FROM cycles ORDER BY ts", con)
findings = pd.read_sql("SELECT * FROM findings ORDER BY ts", con)
alerts = pd.read_sql("SELECT * FROM alerts ORDER BY ts DESC", con)
if cycles.empty:
    st.info("The monitor has not completed a cycle yet.")
    st.stop()
for df in (cycles, findings, alerts):
    df["time"] = pd.to_datetime(df["ts"], unit="s", utc=True).dt.tz_convert("Asia/Singapore").dt.strftime("%H:%M")

feeds = sorted(cycles["feed"].unique())
feed = st.selectbox("Feed", feeds) if len(feeds) > 1 else feeds[0]
c = cycles[cycles["feed"] == feed]
f = findings[findings["feed"] == feed]
a = alerts[alerts["feed"] == feed]
last = c.iloc[-1]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Status now", "Healthy" if last["healthy"] else "Degraded")
col2.metric("Healthy cycles", f"{c['healthy'].mean():.0%}")
col3.metric("Alerts", len(a))
col4.metric("Cycles checked", len(c))
if not last["healthy"]:
    open_now = f[f["ts"] == last["ts"]]
    for _, r in open_now.iterrows():
        st.error(f"**{r['fault']}** at {r['location']}: {r['detail']}")

st.subheader("Traffic: mirrored vs delivered to the tool (Gbps)")
st.caption("The gap between the lines is traffic the tool never received.")
st.line_chart(pd.DataFrame({"mirrored (should reach the tool)": c["offered_gbps"].values,
                            "delivered to the tool": c["delivered_gbps"].values}, index=c["time"].values),
              color=["#9AA4B2", "#1F77B4"])
LABEL = {"path_loss": "Packets lost along the path (%)", "link_errors": "Damaged frames (%)"}
if f.empty:
    st.success("No loss or errors recorded.")
else:
    cols = st.columns(max(1, f["fault"].nunique()))
    for col, fault in zip(cols, sorted(f["fault"].unique())):
        s = f[f["fault"] == fault].groupby("ts")["metric"].max().reindex(c["ts"]).fillna(0) * 100
        s.index = c["time"].values
        with col:
            st.markdown(f"**{LABEL.get(fault, fault)}**")
            st.line_chart(s.rename(fault), height=220)

st.subheader("Alerts")
if a.empty:
    st.success("No alerts.")
for _, r in a.iterrows():
    (st.error if r["kind"] == "DEGRADED" else st.success)(f"**{r['time']} {r['kind']}**: {r['message']}")
