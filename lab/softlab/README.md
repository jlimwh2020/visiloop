# Soft lab: the VisiLoop lab tests with no equipment

The real lab kit (`lab/`) needs a Catalyst 9300, a Cubro EXA48800 and TAPs. The soft lab runs the same tests
on a virtual lab built from real Linux network interfaces. The packets, TCP sessions, captures and SNMP are
all real. Only the switch, TAP and broker are software.

```
 lab client ── gi1 ┐                       ┌ gi2 ── lab server      (25 Mbit/s access links)
                   └──── switch (bridge) ──┘
        TAP legs tapa/tapb ──► P1/P2   SPAN Gi1/0/24 (40 Mbit/s) ──► P3   ERSPAN Te1/1/1 ──► P4
                              packet broker (rules: slicing, VLAN, dedup, ERSPAN stripping)
                 P5 tool port (150 Mbit/s) ──► tool NIC 1, recorded with dumpcap
                 P6 lossless copy           ──► tool NIC 2
 SNMP v2c: switch 172.30.0.2, broker 172.30.0.6 (community visiloop-ro), live IF-MIB counters
```

| Part | How it works |
|---|---|
| Hosts | Two network namespaces. Real HTTP, HTTPS (self-signed), DNS and iperf3 traffic over links shaped to 25 Mbit/s with tbf. |
| Switch | A Linux bridge, plus a daemon (`switchd.py`) that copies frames from raw sockets. It acts as the TAP legs, the SPAN session (rx, tx or both, from any port) and an ERSPAN type II session. The SPAN destination sends at its line rate from a 256 KB buffer (about 50 ms at 40 Mbit/s) and discards when the buffer overflows, as a real port does. |
| Broker | A daemon (`brokerd.py`) with rules from input to output ports: slicing, per-port VLAN tagging, VLAN stripping, deduplication and ERSPAN stripping. Inputs are merged in kernel-timestamp order. Output ports are paced at their line rate with a buffer. For counter tests it can add link loss or damaged frames on an input. |
| Tool | A namespace whose NICs are recorded with dumpcap, as the laptop records the EXA's tool port. |
| Timing | Python forwards frames when it gets the CPU, so the moment a daemon sends a frame says little about when a real port would have. Every frame is scheduled from its kernel arrival time on the lab link and paced at each port's line rate; buffers are virtual queues on that schedule. The scheduled departure travels with the frame in a 20-byte trailer (with the time the original frame was on the lab link), like a packet broker's hardware timestamp. The broker holds frames 150 ms and handles them in trailer order, so a copy the switch daemon sent late still merges in its place, and each recording is re-timed from the broker's trailer (`retime.py`), which is then removed. So the daemons' pauses never show in what VisiLoop measures. |
| Counters | Counts are filed on the lab's wire clock (when the frame was on the lab link) and served as of three seconds ago, so frames in flight between the two daemons are never counted by one and not yet by the other: real devices copy in microseconds. |
| Counters | Each daemon answers SNMP on its management address from its live counters at the moment of the request. VisiLoop reads them with the same code it uses for a Catalyst or an EXA. |

Speeds are lower than the real lab, because Python forwards every frame. Each test's tool profile uses the
soft lab's tool port speed, recorded in the manifest as `tool_port_gbps`.

## Run it

On Linux, or WSL 2 on Windows, as root:

```
sudo apt install iproute2 ethtool iperf3 openssl tshark      # tshark brings dumpcap
pip install -r requirements.txt
sudo python3 -m lab.softlab.run                  # all tests, counters and the monitor: about 30 minutes
sudo python3 -m lab.softlab.run --only L07_slicing C05_crc_errors      # some tests again (merged into the results)
sudo python3 -m lab.softlab.run --monitor-only   # only the continuous-monitoring test
sudo python3 -m lab.softlab.run --down           # remove the virtual lab if a run was interrupted
```

Results go to `RESULTS.md` and `results.json`, recordings to `captures/` (not in git). Use a machine with at
least two cores and little else running: the switch and broker are Python, and under heavy load they fall
behind (the timing stays right thanks to the timestamps, but a run reports any frame a daemon could not read). To score the
recordings again: `python lab/run_lab.py --captures lab/softlab/captures --out lab/softlab`.

## What it covers

- **Capture tests** (`plan.yaml`, `tests`): L01-L12 and L14 from the real plan, plus the fix proofs L03b and
  L14b (deduplication on) and L08b (ERSPAN stripping on). L13 needs several busy links and is left to the
  real lab.
- **Counter tests** (`counter_tests`): healthy, SPAN oversubscription, broker congestion, loss on the link
  into the broker, and damaged frames. Each one is located over SNMP.
- **Continuous monitoring** (`monitor`): VisiLoop's monitor polls the SPAN path every 5 s while faults come
  and go. It should raise a DEGRADED alert when each fault starts and RECOVERED when it clears.

## What it found

Building the soft lab found four real problems in VisiLoop (slicing hidden by a receive-only SPAN, network loss
reported as monitoring loss, counter readings taken too far apart, one alert per fault type) and one in the
real-lab plan (a full-speed download fills a 1G tool port). All are fixed; the main [README](../../README.md)
explains each one.

## What it does not prove

It is not Cisco or Cubro. Real hardware timing, real ASIC buffers, real optics and real CRC errors still
need the real lab: `lab/LAB_SETUP.md` and the lab-day runbook.
