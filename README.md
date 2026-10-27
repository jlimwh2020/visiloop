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

## Responsible use
VisiLoop is a defensive tool for owners of a network to make sure their own monitoring receives complete traffic. It never pushes changes to equipment; every fix needs engineer approval. Test data is synthetic or from public datasets.
