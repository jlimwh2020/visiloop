# VisiLoop benchmark suite: results

**200 generated test cases** across four tool types (IDS, NDR, APM, SIEM), with 0 to 3 faults each, near-threshold faults, below-threshold noise and tool-awareness traps. The answer key is computed by the generator directly from the packets it wrote, independently of VisiLoop's checks. Cases too close to a threshold to label fairly are regenerated. See `make_suite.py`.

| Case type | Cases |
|---|---|
| clean: healthy feed | 20 |
| mild: only below-threshold faults (must not alarm) | 30 |
| single: one fault | 60 |
| double: two faults | 50 |
| triple: three faults | 25 |
| tool_aware: heavy TLS or untagged traffic on a tool that tolerates it (must not alarm) | 15 |

**What this shows, and what it doesn't.** The checks are deterministic, and the suite leaves a no-label zone around each threshold, so a perfect check score mainly proves the checks are correct and robust across tools, traffic mixes and fault combinations. The harder test is Muse Spark: it must call the right checks, report every fault and no others, and pick a sensible fix. All traffic is synthetic; real captures are the next step.

## Headline

- **Muse Spark diagnosis exactly right on 198/200 (99.0%) cases**, overall precision 100.0%, recall 99.1%.
- **Tool-aware view: 200/200 (100.0%) exactly right, sensible fix 231/231 (100.0%).** Every disagreement with the strict key was Muse Spark applying the tool's profile (see section 3).
- **Sensible fix chosen 231/233 (99.1%)** of the time; **0 ungrounded claims** reached the guard.
- **Checks exactly right on 200/200 (100.0%) cases.**
- **189/189 (100.0%) fixable faults verified fixed** in the simulated broker; 46 decryption items reported as advice.
- **US$2.15 for all 200 diagnoses** (US$0.0108 each), median 9.8 s, 95th percentile 15.3 s.

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
| APM | 33/33 (100.0%) |
| IDS | 71/71 (100.0%) |
| NDR | 64/64 (100.0%) |
| SIEM | 32/32 (100.0%) |

| Difficulty | Exactly right |
|---|---|
| clear | 170/170 (100.0%) |
| near threshold | 30/30 (100.0%) |

## 2. Fix and prove (simulated broker, free)

- Fixable faults verified fixed: **189/189 (100.0%)**
- Advice-only items (decryption, cannot be simulated offline): **46**
- Cases healthy after the fixes: **135/135 (100.0%)** of cases with faults
- Load-balanced tool groups sized from 2 to 11 ports (median 4)

## 3. Muse Spark diagnosis (muse-spark-1.2, recorded 2026-10-28)

Exactly right on **198/200 (99.0%)** cases. Tokens: 564,953 in, 340,423 out.

| Fault | Found | Missed | False alarms | Precision | Recall |
|---|---|---|---|---|---|
| duplicates | 35 | 0 | 0 | 100.0% | 100.0% |
| one_way | 30 | 2 | 0 | 100.0% | 93.8% |
| packet_drops | 29 | 0 | 0 | 100.0% | 100.0% |
| tool_overload | 49 | 0 | 0 | 100.0% | 100.0% |
| encrypted_share | 46 | 0 | 0 | 100.0% | 100.0% |
| missing_vlan | 44 | 0 | 0 | 100.0% | 100.0% |
| **All faults** | 233 | 2 | 0 | 100.0% | 99.1% |

| Case type | Exactly right |
|---|---|
| clean | 20/20 (100.0%) |
| double | 49/50 (98.0%) |
| mild | 30/30 (100.0%) |
| single | 59/60 (98.3%) |
| tool_aware | 15/15 (100.0%) |
| triple | 25/25 (100.0%) |

| Tool | Exactly right |
|---|---|
| APM | 33/33 (100.0%) |
| IDS | 71/71 (100.0%) |
| NDR | 64/64 (100.0%) |
| SIEM | 30/32 (93.8%) |

| Difficulty | Exactly right |
|---|---|
| clear | 168/170 (98.8%) |
| near threshold | 30/30 (100.0%) |

### Where Muse Spark disagreed with the strict answer key

The strict key counts one-way traffic as a fault on every tool. VisiLoop's own tool profiles say a SIEM does not need both directions, and Muse Spark applied that: in every SIEM case with one-way traffic it either left the fault out or reported it with "no broker change needed". The one-way check itself ignores the tool profile, so this is a gap in the check, found by the agent.

- `s076_single`: "Feed s076_single is healthy for SIEM delivery. No packet drops, overload, duplicates, VLAN gaps or excessive encryption. 35.8% one-way TCP sessions detected (73/204) but SIEM profile needs_both_directions=false so covera"
- `s110_single`: "SIEM feed s110_single is healthy. Duplicates, encrypted share, VLAN coverage (10,20), packet drops and tool overload all healthy. One-way traffic detected (23/113 sessions, 20.4%) but SIEM profile needs_both_directions=f"
- `s124_double`: "Feed s124_double to SIEM is degraded due to tool overload: 2.24 Gbps microbursts exceed 1 Gbps SIEM port (224% capacity, 6 intervals) causing drops and event loss. One-way traffic (21.2% sessions) was detected but is tol"
- `s125_double`: "SIEM feed s125_double is degraded by 14.7% duplicate packets (392/2673); 66.7% one-way TCP sessions (142/213) also detected but tolerable for this SIEM which does not require bidirectional flows."

Scored tool-aware (one-way optional on tools that don't need both directions): **200/200 (100.0%)** exactly right, sensible fix **231/231 (100.0%)**.

Faults the checks found but Muse Spark left out of its answer:

- `s110_single`: one_way
- `s124_double`: one_way

Fix choices outside the accepted set:

- `s076_single` one_way: `none`
- `s125_double` one_way: `none`

## Reproduce

```
python bench/suite/make_suite.py        # 200 cases, deterministic (seed 2026)
python bench/suite/run_suite.py         # checks + fix loop (free)
python bench/suite/run_suite_agent.py   # Muse Spark (about US$2, resumable, capped)
python bench/suite/make_report.py       # this file
```
