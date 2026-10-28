# VisiLoop benchmark suite v3: results

Version 3 adds three faults (packet slicing, tunnel encapsulation, oversize frames), tool-awareness traps for them, and a fix loop that re-checks a load-balanced tool group as a whole and plans a second round when a fix reveals a hidden fault. Version 2 made the one-way check tool-aware, a gap Muse Spark found in version 1. Earlier results: [results/RESULTS_v2.md](results/RESULTS_v2.md), [results/RESULTS_v1.md](results/RESULTS_v1.md).

**200 generated test cases** across four tool types (IDS, NDR, APM, SIEM), with 0 to 3 faults each, near-threshold faults, below-threshold noise and tool-awareness traps. The answer key is computed by the generator directly from the packets it wrote, independently of VisiLoop's checks. Cases too close to a threshold to label fairly are regenerated. See `make_suite.py`.

| Case type | Cases |
|---|---|
| clean: healthy feed | 20 |
| mild: only below-threshold faults (must not alarm) | 30 |
| single: one fault | 60 |
| double: two faults | 50 |
| triple: three faults | 25 |
| tool_aware: traffic a tool tolerates: heavy TLS, untagged, one-way, sliced or jumbo (must not alarm) | 15 |

**What this shows, and what it doesn't.** The checks are deterministic, and the suite leaves a no-label zone around each threshold, so a perfect check score mainly proves the checks are correct and robust across tools, traffic mixes and fault combinations. The harder test is Muse Spark: it must call the right checks, report every fault and no others, and pick a sensible fix. All traffic is synthetic; real captures are the next step.

## Headline

- **Muse Spark diagnosis exactly right on 200/200 (100.0%) cases**, overall precision 100.0%, recall 100.0%.
- **Sensible fix chosen 224/235 (95.3%)** of the time; **0 ungrounded claims** reached the guard.
- **Checks exactly right on 200/200 (100.0%) cases.**
- **179/179 (100.0%) fixable faults verified fixed** in the simulated broker; 56 decryption items reported as advice.
- **US$2.30 for all 200 diagnoses** (US$0.0115 each), median 11.9 s, 95th percentile 17.1 s.

## 1. Checks (deterministic, free)

Exactly right on **200/200 (100.0%)** cases.

| Fault | Found | Missed | False alarms | Precision | Recall |
|---|---|---|---|---|---|
| duplicates | 26 | 0 | 0 | 100.0% | 100.0% |
| one_way | 27 | 0 | 0 | 100.0% | 100.0% |
| packet_drops | 27 | 0 | 0 | 100.0% | 100.0% |
| tool_overload | 24 | 0 | 0 | 100.0% | 100.0% |
| encrypted_share | 29 | 0 | 0 | 100.0% | 100.0% |
| missing_vlan | 21 | 0 | 0 | 100.0% | 100.0% |
| truncated | 22 | 0 | 0 | 100.0% | 100.0% |
| tunnel | 32 | 0 | 0 | 100.0% | 100.0% |
| oversize | 27 | 0 | 0 | 100.0% | 100.0% |
| **All faults** | 235 | 0 | 0 | 100.0% | 100.0% |

| Tool | Exactly right |
|---|---|
| APM | 26/26 (100.0%) |
| IDS | 81/81 (100.0%) |
| NDR | 55/55 (100.0%) |
| SIEM | 38/38 (100.0%) |

| Difficulty | Exactly right |
|---|---|
| clear | 155/155 (100.0%) |
| near threshold | 45/45 (100.0%) |

## 2. Fix and prove (simulated broker, free)

- Fixable faults verified fixed: **179/179 (100.0%)**
- Advice-only items (decryption point or MTU change on the customer side, cannot be simulated offline): **56**
- Cases healthy after the fixes: **135/135 (100.0%)** of cases with faults
- Load-balanced tool groups sized from 2 to 21 ports (median 5.5)

## 3. Muse Spark diagnosis (muse-spark-1.2, recorded 2026-10-29)

Exactly right on **200/200 (100.0%)** cases. Tokens: 664,279 in, 346,315 out.

| Fault | Found | Missed | False alarms | Precision | Recall |
|---|---|---|---|---|---|
| duplicates | 26 | 0 | 0 | 100.0% | 100.0% |
| one_way | 27 | 0 | 0 | 100.0% | 100.0% |
| packet_drops | 27 | 0 | 0 | 100.0% | 100.0% |
| tool_overload | 24 | 0 | 0 | 100.0% | 100.0% |
| encrypted_share | 29 | 0 | 0 | 100.0% | 100.0% |
| missing_vlan | 21 | 0 | 0 | 100.0% | 100.0% |
| truncated | 22 | 0 | 0 | 100.0% | 100.0% |
| tunnel | 32 | 0 | 0 | 100.0% | 100.0% |
| oversize | 27 | 0 | 0 | 100.0% | 100.0% |
| **All faults** | 235 | 0 | 0 | 100.0% | 100.0% |

| Case type | Exactly right |
|---|---|
| clean | 20/20 (100.0%) |
| double | 50/50 (100.0%) |
| mild | 30/30 (100.0%) |
| single | 60/60 (100.0%) |
| tool_aware | 15/15 (100.0%) |
| triple | 25/25 (100.0%) |

| Tool | Exactly right |
|---|---|
| APM | 26/26 (100.0%) |
| IDS | 81/81 (100.0%) |
| NDR | 55/55 (100.0%) |
| SIEM | 38/38 (100.0%) |

| Difficulty | Exactly right |
|---|---|
| clear | 155/155 (100.0%) |
| near threshold | 45/45 (100.0%) |

Fix choices outside the accepted set:

- `s061_single` oversize: `slice`
- `s121_double` oversize: `slice`
- `s130_double` oversize: `slice`
- `s140_double` packet_drops: `disable_slicing`
- `s150_double` oversize: `slice`
- `s154_double` packet_drops: `disable_slicing`
- `s156_double` packet_drops: `disable_slicing`
- `s165_triple` packet_drops: `disable_slicing`
- `s171_triple` oversize: `slice`
- `s180_triple` oversize: `slice`
- `s181_triple` oversize: `slice`

Muse Spark only chooses and explains the fix; the broker settings themselves come from VisiLoop's deterministic fix plug-in for each fault, so a mislabelled choice does not change the configuration that is proposed and verified.

## Reproduce

```
python bench/suite/make_suite.py        # 200 cases, deterministic (seed 2026)
python bench/suite/run_suite.py         # checks + fix loop (free)
python bench/suite/run_suite_agent.py   # Muse Spark (about US$2, resumable, capped)
python bench/suite/make_report.py       # this file
```
