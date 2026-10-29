# VisiLoop soft lab results: real packets, no equipment

**16/16 lab tests** gave exactly the expected result. Each test set up one fault on purpose on the soft lab: a virtual switch, TAP and packet broker on real Linux network interfaces, carrying real TCP, HTTP, HTTPS, DNS and iperf3 traffic between a lab client and server. The tool port was recorded with dumpcap, as the laptop would in the real lab (see `README.md` and `plan.yaml`).

| Test | Tool | Expected | VisiLoop found | Fix result | Muse Spark |
|---|---|---|---|---|---|
| L01_baseline | IDS | healthy | ✅ healthy | healthy | - |
| L02_span_rx_only | IDS | one_way | ✅ one_way | healthy | - |
| L03_overlapping_inputs | IDS | duplicates | ✅ duplicates | healthy (simulated; no broker-input capture) | - |
| L03b_dedup_on | IDS | healthy | ✅ healthy | healthy | - |
| L04_span_oversubscribed | IDS | packet_drops | ✅ packet_drops | healthy except advice items (simulated; no broker-input capture) | - |
| L05_burst | IDS | packet_drops, tool_overload | ✅ packet_drops, tool_overload | still broken | - |
| L06_vlan_stripped | IDS | missing_vlan | ✅ missing_vlan | healthy | - |
| L07_slicing | IDS | truncated | ✅ truncated | healthy | - |
| L08_tunnel | IDS | oversize, tunnel | ✅ oversize, tunnel | healthy except advice items (simulated; no broker-input capture) | - |
| L08b_tunnel_stripped | IDS | healthy | ✅ healthy | healthy | - |
| L09_jumbo | IDS | oversize | ✅ oversize | healthy except advice items (simulated; no broker-input capture) | - |
| L10_encrypted | IDS | encrypted_share | ✅ encrypted_share | healthy except advice items (simulated; no broker-input capture) | - |
| L11_combined | IDS | one_way, truncated | ✅ one_way, truncated | healthy | - |
| L12_siem_tolerates_slicing | SIEM | healthy | ✅ healthy | healthy | - |
| L14_double_tapped | IDS | duplicates | ✅ duplicates | healthy (simulated; no broker-input capture) | - |
| L14b_dedup_on | IDS | healthy | ✅ healthy | healthy | - |

## Details

**L01_baseline**
- no faults found

**L02_span_rx_only**
- one_way: 84 of 84 TCP sessions show only one direction (100.0%)

**L03_overlapping_inputs**
- duplicates: 41763 of 83526 packets are duplicates (50.0%)

**L03b_dedup_on** (VisiLoop's fix for L03, deduplication on in the broker, proven on the same setup.)
- no faults found

**L04_span_oversubscribed**
- packet_drops: 23691 of 104848 TCP packets show evidence of missing data (22.6%). Not counted: 4 gaps that retransmissions filled later (packets lost on the network before the monitoring point, which the feed rightly shows)

**L05_burst** (Both TAP legs together offer up to 50 Mbit/s to a 40 Mbit/s tool port, so the port overflows and really loses packets, as the real lab's 1G P5 does with two 1G legs.)
- packet_drops: 7086 of 70373 TCP packets show evidence of missing data (10.1%). Not counted: 89 gaps that retransmissions filled later (packets lost on the network before the monitoring point, which the feed rightly shows)
- tool_overload: Peak 0.05 Gbps in a 1 ms burst vs a 0.04 Gbps IDS port (130% of capacity, 9112 overloaded intervals)
- fix load_balance (not fixed): One flow alone bursts to 0.049 Gbps, 121% of a 0.04 Gbps port. Flow hashing keeps a flow on one port, so load balancing cannot fix this: use a faster tool port (one 0.12 Gbps tool port).

**L06_vlan_stripped**
- missing_vlan: required VLAN(s) 10, 20 not seen; 100% of packets untagged

**L07_slicing**
- truncated: 24379 of 40276 frames are cut short (60.5%), most to 128 bytes; this IDS needs the full payload
- fix disable_slicing (verified fixed): if bandwidth is the reason for slicing, load balance or filter instead

**L08_tunnel** (ERSPAN adds 50 bytes, so full-size frames arrive as 1564 bytes, over an IDS port's 1518.)
- oversize: 25427 of 42743 frames (59.5%) are larger than the 1518-byte maximum of this IDS port (largest 1564 bytes); its network card drops them. This tool needs the full payload, so trimming frames to fit is not an option.
- tunnel: 42743 of 42743 frames (100.0%) arrive inside a tunnel (ERSPAN 42743)

**L08b_tunnel_stripped** (VisiLoop's fix for L08, ERSPAN header stripping on in the broker.)
- no faults found

**L09_jumbo** (P5 at 400 Mbit/s here, so two 9 KB frames in one millisecond are not a burst on this lab's slow port.)
- oversize: 6364 of 12285 frames (51.8%) are larger than the 1518-byte maximum of this IDS port (largest 9014 bytes); its network card drops them. This tool needs the full payload, so trimming frames to fit is not an option.

**L10_encrypted**
- encrypted_share: 100% of bytes are encrypted; this IDS tolerates about 60%

**L11_combined**
- one_way: 81 of 81 TCP sessions show only one direction (100.0%)
- truncated: 135 of 16003 frames are cut short (0.8%), most to 128 bytes; this IDS needs the full payload; 100% of the 135 frames longer than 128 bytes were cut
- fix disable_slicing (verified fixed): if bandwidth is the reason for slicing, load balance or filter instead

**L12_siem_tolerates_slicing**
- no faults found

**L14_double_tapped** (The same traffic seen on two links (TAP on the client link, SPAN of the server port) in one rule.)
- duplicates: 41654 of 83308 packets are duplicates (50.0%)

**L14b_dedup_on** (VisiLoop's fix for L14, deduplication on.)
- no faults found


## Counter tests: real SNMP

**5/5** located correctly. VisiLoop read the virtual switch and broker over SNMP v2c (IF-MIB) before and after the traffic, as it reads a Catalyst and an EXA.

| Test | Path | Expected | VisiLoop found | Fix |
|---|---|---|---|---|
| C01_healthy | span | healthy | ✅ healthy | - |
| C02_span_oversubscribed | span | path_loss at LAB-SW Gi1/0/24 | ✅ path_loss at LAB-SW Gi1/0/24 | replace_span_with_tap (advice (confirm by reading the counters after the change)) |
| C03_broker_congestion | tap | path_loss at LAB-NPB P5 | ✅ path_loss at LAB-NPB P5 | load_balance (advice (confirm by reading the counters after the change)) |
| C04_link_loss | span | path_loss at LAB-NPB P3 | ✅ path_loss at LAB-NPB P3 | check_link (advice (confirm by reading the counters after the change)) |
| C05_crc_errors | span | link_errors at LAB-NPB P3 | ✅ link_errors at LAB-NPB P3 | check_link (advice (confirm by reading the counters after the change)) |

- **C02_span_oversubscribed**: the SPAN session should copy 118,275 packets from LAB-SW Gi1/0/1 (mirrored) but LAB-SW Gi1/0/24 (SPAN destination) sent only 105,255: 0.05 Gbps mirrored into a 0.04 Gbps destination port (11.01% lost); LAB-SW Gi1/0/24 (SPAN destination) discarded 13,020 packets on output: about 0.04 Gbps offered to a 0.04 Gbps port (average load 98%; bursts are higher) (11.01% lost)
- **C03_broker_congestion**: LAB-NPB P5 (to the tool) discarded 27,481 packets on output: about 0.04 Gbps offered to a 0.03 Gbps port (average load 99%; bursts are higher) (23.94% lost)
- **C04_link_loss**: LAB-SW Gi1/0/24 (SPAN destination) sent 42,450 packets but LAB-NPB P3 (SPAN input) saw only 41,570: lost on the link between them (cable, optic or an unmonitored device) (2.07% lost)
- **C05_crc_errors**: LAB-NPB P3 (SPAN input) received 202 damaged frames (CRC/alignment errors): a faulty cable, optic or duplex mismatch on the link into it

## Continuous monitoring

VisiLoop's monitor polled the SPAN path over SNMP every 5 s while faults were switched on and off:

| Time | Phase |
|---|---|
| 2 s | healthy |
| 23 s | link loss into P3 |
| 46 s | healthy |
| 68 s | damaged frames into P3 |
| 90 s | healthy |
| 112 s | SPAN overload |
| 134 s | healthy |

Alerts it raised:

```
DEGRADED softlab-ids: path_loss at LAB-NPB P3 (1.80%): LAB-SW Gi1/0/24 (SPAN destination) sent 8,775 packets but LAB-NPB P3 (SPAN input) saw only 8,617: lost on the link between them (cable, optic or an unmonitored device) (1.80% lost)
RECOVERED softlab-ids: path_loss at LAB-NPB P3 cleared; feed healthy
DEGRADED softlab-ids: link_errors at LAB-NPB P3 (0.20%): LAB-NPB P3 (SPAN input) received 17 damaged frames (CRC/alignment errors): a faulty cable, optic or duplex mismatch on the link into it
RECOVERED softlab-ids: link_errors at LAB-NPB P3 cleared; feed healthy
DEGRADED softlab-ids: path_loss at LAB-SW Gi1/0/24 (21.12%): the SPAN session should copy 8,785 packets from LAB-SW Gi1/0/1 (mirrored) but LAB-SW Gi1/0/24 (SPAN destination) sent only 6,930: 0.01 Gbps mirrored into a 0.01 Gbps destination port (21.12% lost); LAB-SW Gi1/0/24 (SPAN destination) discarded 1,855 packets on output: about 0.01 Gbps offered to a 0.01 Gbps port (average load 71%; bursts are higher) (21.12% lost)
RECOVERED softlab-ids: path_loss at LAB-SW Gi1/0/24 cleared; feed healthy
```
