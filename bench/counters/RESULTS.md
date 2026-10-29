# Counter benchmark: results

**100 simulated feed paths** (SPAN or TAP into a broker, with or without tool counters, 1G or 10G), each with 0-2 faults from: SPAN oversubscription, broker congestion, damaged frames, tool capture overrun and loss on a link, plus below-threshold noise that must not alarm. The answer key records each fault and where it is. See `make_counter_suite.py`.

## Counter checks (free)

| Measure | Result |
|---|---|
| Right faults, at the right place | **100/100 (100%)** |
| Healthy or below-threshold paths kept quiet | 31/31 (100%) |
| Fix suited to where the problem is | 69/69 (100%) |

| Fault | Found at the right place |
|---|---|
| broker congestion | 14/14 (100%) |
| crc errors | 20/20 (100%) |
| link loss | 14/14 (100%) |
| nic overrun | 31/31 (100%) |
| span oversubscribed | 21/21 (100%) |

## Muse Spark diagnosis from counters

| Measure | Result |
|---|---|
| Exactly the right faults | **69/69 (100%)** |
| Fix suited to where the problem is | **68/69 (99%)** |
| Ungrounded claims removed by the guard | 0 |
| Cost | US$0.89 for 69 paths (US$0.0129 each) |

Where Muse Spark differed:

- `c015_broker` (broker_congestion): reported ['path_loss'], fixes {'path_loss': 'tool_capacity'}

Reproduce: `python bench/counters/make_counter_suite.py` then `python bench/counters/run_counter_suite.py [--agent]`.
