# VisiLoop lab kit: prove the checks on real traffic

Fifteen tests: one fault each, one that verifies a fix, and two optional multi-link tests, set up on purpose on lab TAPs, switches and packet brokers.
The capture laptop plays the security tool. **Lab traffic only**: never customer, production
or personal traffic. `capture.py` asks you to confirm this before recording anything.

## What you need

- A lab client and a lab web server (HTTP and HTTPS), with `iperf3` on both for the load tests
- A passive TAP on the client-server link, a lab switch that can SPAN (and ERSPAN for L08), a packet broker
- The capture laptop with Wireshark installed, plugged into the broker tool port
- Optional: a second interface on the laptop for the lossless broker input (TAP output), so fixes can be
  verified on real traffic (tests marked `ingress: true`)

## Run it

```
python lab/capture.py --list                            # find the interface numbers
python lab/capture.py --iface 5 --seconds 10 --only L01_baseline   # 10-second dry run first
python lab/capture.py --iface 5 --ingress-iface 6       # all tests, about 45-60 minutes
python lab/run_lab.py                                   # score them (free)
python lab/run_lab.py --agent                           # add Muse Spark (about US$0.15)
```

For each test the script shows what to set up, what traffic to run and what to undo afterwards.
Already-recorded tests are skipped; `--redo L05_burst` records one again. If the laptop itself drops
packets during a capture, the script warns you: that test's result would not be trustworthy.

## The tests

| Test | Fault set up | VisiLoop should report |
|---|---|---|
| L01_baseline | none: TAP, both legs to the tool | healthy |
| L02_span_rx_only | SPAN mirroring received traffic only | one-way traffic |
| L03_overlapping_inputs | TAP and SPAN of the same link on one tool port | duplicates |
| L04_span_oversubscribed | several busy ports spanned to one 1G destination | packet drops |
| L05_burst | 2-second bursts at 2-3x the tool port speed | tool overload |
| L06_vlan_stripped | broker strips VLAN tags | missing VLANs |
| L07_slicing | slicing at 128 bytes on the tool port | packet slicing |
| L08_tunnel | ERSPAN/GRE/VXLAN session without tunnel stripping | tunnel headers |
| L08b_tunnel_stripped | the same session with stripping on (VisiLoop's fix) | healthy |
| L09_jumbo | MTU 9000 hosts, 1518-byte tool port | oversize frames |
| L10_encrypted | HTTPS only | encrypted share |
| L11_combined | RX-only SPAN plus slicing | one-way traffic, packet slicing |
| L12_siem_tolerates_slicing | slicing, judged as a SIEM feed | healthy (a SIEM does not need the payload) |
| L13_multi_link_overload (optional) | 2-4 tapped fibre links aggregated onto one 1G tool port | tool overload |
| L14_double_tapped (optional) | the same traffic tapped on two links, dedup off | duplicates |

The plan and [LAB_SETUP.md](LAB_SETUP.md) are written for a Cisco Catalyst C9300-24T-E and a Cubro EXA48800, with
a port plan and the exact switch commands for each test. For other equipment, edit `plan.yaml`: speeds, VLAN
numbers, the tool profile per test, capture length.

## Notes

- A 1G laptop port cannot show bursts above 1 Gbps, so L05 proves the detection but not the size of
  the tool group needed. Broker port counters (`visikit/counters`) show the real offered load.
- Captures are saved to `lab/captures/`, which git ignores. Even lab captures can contain lab
  passwords or internal addresses: review them before sharing.
- Results are written to `lab/RESULTS.md`.
