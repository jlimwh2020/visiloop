# VisiLoop benchmark suite v2: results

Version 2 makes the one-way check tool-aware (a gap Muse Spark found in version 1) and adds one-way traps on SIEM tools. Version 1 results: [results/RESULTS_v1.md](results/RESULTS_v1.md).

**200 generated test cases** across four tool types (IDS, NDR, APM, SIEM), with 0 to 3 faults each, near-threshold faults, below-threshold noise and tool-awareness traps. The answer key is computed by the generator directly from the packets it wrote, independently of VisiLoop's checks. Cases too close to a threshold to label fairly are regenerated. See `make_suite.py`.

| Case type | Cases |
|---|---|
| clean: healthy feed | 20 |
| mild: only below-threshold faults (must not alarm) | 30 |
| single: one fault | 60 |
| double: two faults | 50 |
| triple: three faults | 25 |
| tool_aware: heavy TLS, untagged or one-way traffic on a tool that tolerates it (must not alarm) | 15 |

**What this shows, and what it doesn't.** The checks are deterministic, and the suite leaves a no-label zone around each threshold, so a perfect check score mainly proves the checks are correct and robust across tools, traffic mixes and fault combinations. The harder test is Muse Spark: it must call the right checks, report every fault and no others, and pick a sensible fix. All traffic is synthetic; real captures are the next step.

## 1. Checks (deterministic, free)

Exactly right on **200/200 (100.0%)** cases.

| Fault | Found | Missed | False alarms | Precision | Recall |
|---|---|---|---|---|---|
| duplicates | 35 | 0 | 0 | 100.0% | 100.0% |
| one_way | 32 | 0 | 0 | 100.0% | 100.0% |
| packet_drops | 29 | 0 | 0 | 100.0% | 100.0% |
| tool_overload | 49 | 0 | 0 | 100.0% | 100.0% |
| encrypted_share | 46 | 0 | 0 | 100.0% | 100.0% |
| missing_vlan | 44 | 0 | 0 | 100.0% | 100.0% |
| **All faults** | 235 | 0 | 0 | 100.0% | 100.0% |

| Tool | Exactly right |
|---|---|
| APM | 29/29 (100.0%) |
| IDS | 79/79 (100.0%) |
| NDR | 65/65 (100.0%) |
| SIEM | 27/27 (100.0%) |

| Difficulty | Exactly right |
|---|---|
| clear | 174/174 (100.0%) |
| near threshold | 26/26 (100.0%) |

## 2. Fix and prove (simulated broker, free)

- Fixable faults verified fixed: **189/189 (100.0%)**
- Advice-only items (decryption, cannot be simulated offline): **46**
- Cases healthy after the fixes: **135/135 (100.0%)** of cases with faults
- Load-balanced tool groups sized from 2 to 11 ports (median 4)

## 3. Muse Spark diagnosis

Not run yet: `python bench/suite/run_suite_agent.py`

## Reproduce

```
python bench/suite/make_suite.py        # 200 cases, deterministic (seed 2026)
python bench/suite/run_suite.py         # checks + fix loop (free)
python bench/suite/run_suite_agent.py   # Muse Spark (about US$2, resumable, capped)
python bench/suite/make_report.py       # this file
```
