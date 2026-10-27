# VisiLoop

**Your security tools may be blind. VisiLoop finds out why, fixes it, and proves it.**

VisiLoop checks the traffic feeds that TAPs, SPAN ports and packet brokers deliver to security tools (NDR, IDS, SIEM). It diagnoses feed faults, writes a vendor-neutral packet broker fix, and verifies the fix in a simulated broker. Built for the Meta Global AI Developer Hackathon (Indie Developer track).

## How it works
1. **See:** SAM 3.1 + Muse Spark read the network diagram.
2. **Diagnose:** detectors measure each feed; a Muse Spark agent explains the root cause.
3. **Fix:** a vendor-neutral broker configuration is generated.
4. **Prove:** the fix is simulated on the capture and the feed is re-scored.

## VisiKit framework
Every fault check and every fix is a small plug-in.

```
visikit/
  core/        schema.py (Finding, Fix, ToolProfile, FeedContext), registry.py, tools.py, runner.py
  detectors/   one file per fault: duplicates, one_way, packet_drops, tool_overload, encrypted_share, missing_vlan
  fixes/       one file per fix: dedup, ...
  profiles/    tools.yaml: what each tool type needs
bench/
  make_clean.py  generates a healthy synthetic capture
  inject.py      creates one damaged capture per fault + manifest.json (answer key)
  run_bench.py   runs all detectors and scores them
```

Add a detector:
```python
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding

@detector
class MyCheck:
    fault = "my_fault"
    def run(self, ctx: FeedContext) -> list[Finding]:
        ...
```

## Quick start
Requires Python 3.11+ and Wireshark (with TShark).
```
pip install -r requirements.txt
python bench/inject.py
python bench/run_bench.py
```

## Diagnosis agent (Muse Spark)
The agent gets every detector as a tool, runs the checks, and returns a structured diagnosis
(root cause, impact on the tool, recommended broker fix, evidence frames). A grounding guard
drops any finding that no check returned. Needs `MODEL_API_KEY` set.
```
python -m visikit.agent.diagnose bench/cases/one_way.pcap --tool IDS
python bench/run_agent_bench.py            # score the agent on all cases
python bench/run_agent_bench.py one_way    # or selected cases
```

## Closed loop: diagnose, fix, prove
Each fault's fix plug-in calculates its settings from the measurements (for example, the number of
load-balanced tool ports from the measured 1 ms peak). A simulated broker applies the fixes in order and
every resulting tool port is re-checked. A fault counts as fixed only if no check finds it afterwards.
Decryption advice cannot be verified offline and is reported as advice.
```
python -m visikit.loop bench/cases/one_way.pcap --ingress bench/cases/clean.pcap --tool IDS
python bench/run_loop_bench.py            # free: detectors + fixes + simulator
python bench/run_loop_bench.py --agent    # add Muse Spark explanations (uses API credits)
```

## Diagram vision (SAM 3.1 + Muse Spark)
SAM 3.1 finds every device box on the customer's network diagram. The boxes are numbered on a copy of the
image and Muse Spark reads it into an inventory (devices, links, speeds, TAP/SPAN capture points and the
direction each mirrors). Findings are then pinned onto the devices that explain them and the diagram is redrawn.
The inventory is cached next to the image, so each diagram is read once.
```
python -m visikit.vision.diagram demo/diagram.png --pcap bench/cases/combined.pcap --tool IDS
```

## Detection proof (Suricata)
The breach case contains a harmless test signature in a server response. The IDS feed arrives through an
RX-only SPAN, so Suricata never sees that response. After VisiLoop aggregates both TAP legs, Suricata
raises the alert. Rules: `visikit/proof/visiloop.rules`. On Windows, Suricata runs inside WSL Ubuntu.
```
python bench/run_breach_demo.py     # Suricata alerts: 0 on the broken feed -> 1 after the fix
```

## Dashboard
One page that walks through See -> Diagnose -> Fix -> Prove, with the pinned diagram before and after.
```
python -m streamlit run ui/app.py
```

## Responsible use
VisiLoop is a defensive tool for owners of a network to make sure their own monitoring receives complete traffic. It never pushes changes to equipment; every fix needs engineer approval. Test data is synthetic or from public datasets.
