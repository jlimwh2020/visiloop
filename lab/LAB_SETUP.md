# Lab setup: Cisco Catalyst C9300-24T-E + Cubro EXA48800 + Cubro TAPs

The setup for running VisiLoop's twelve lab tests (`plan.yaml`) on a Catalyst 9300 switch and a Cubro EXA48800
packet broker. **Lab traffic only.** Every change below is undone after its test.

Port numbers are a suggestion: use what is free, and keep this page, `plan.yaml` and `lab_path.yaml` in step.
EXA settings are described by function; the exact menu names depend on the EXA software version.

## Equipment

| Role | Model | Notes |
|---|---|---|
| Switch | Cisco Catalyst C9300-24T-E | see below for the 10G module and ERSPAN licence |
| Packet broker | Cubro EXA48800 | SFP/SFP+ ports: 1G copper SFPs for P1, P2, P3, P5, P6 |
| Copper TAP | Cubro CBR.TAP 10/100/1000-B-R3 | on the 1G client link; the main TAP for the tests |
| Optical TAP | Cubro CBR.Opto-1-MM-R3 | on a multimode fibre link; optional, for L05 and L09 (below) |
| Multi-link optical TAP | Cubro CUB.OPTOSLIM-4L-MM or CUB.OPTOSLIM-8L-MM | 4 or 8 multimode links; optional, for L13 and L14 (below) |

**Copper TAP (CBR.TAP 10/100/1000-B-R3):** an active breakout TAP with two monitor outputs, A and B. It needs its
12 V power supply. If power is lost, its relays connect the link directly, with a short drop, so power it up and
check the client link before recording, and do not unplug it during a test. If the client link goes down, the
monitor outputs follow. Cubro's data sheet does not say whether it passes jumbo frames: use the optical TAP for L09
if the copper TAP drops them.

**Optical TAP (CBR.Opto-1-MM-R3):** fully passive, 50/50 split, multimode (850/1300 nm), LC connectors, any speed up
to 100G, two monitor outputs. It passes everything unchanged, jumbo frames included. Its monitor outputs run at the
link's speed, so the EXA input ports need matching multimode optics (1000BASE-SX for a 1G fibre link,
10GBASE-SR for 10G). The 50/50 split adds optical loss on the live link: keep patch cords short.

## Port plan

```
              Cubro copper TAP (CBR.TAP 10/100/1000-B-R3, powered)
 lab client ── A ──[TAP]── B ── Gi1/0/1  Catalyst 9300  Gi1/0/2 ── lab server
                  │    │                     │ Gi1/0/24 (1G SPAN destination)
                  │    │                     │ Te1/1/1  (10G, ERSPAN to the EXA)
                  ▼    ▼                     ▼
              EXA P1  EXA P2            EXA P3 (1G)   EXA P4 (10G)
                         Cubro EXA48800
              EXA P5 (1G copper SFP) ──► laptop NIC 1   (the "tool": what VisiLoop checks)
              EXA P6 (1G copper SFP) ──► laptop NIC 2   (optional: clean copy of P1+P2 = "ingress")
```

| Port | Connects to | Speed | Role |
|---|---|---|---|
| 9300 Gi1/0/1 | TAP network side (client link) | 1G | client port, SPAN source |
| 9300 Gi1/0/2 | lab server | 1G | server port |
| 9300 Gi1/0/24 | EXA P3 | 1G | SPAN destination |
| 9300 Te1/1/1 | EXA P4 | 10G | ERSPAN (routed link) |
| EXA P1, P2 | copper TAP monitor A and B | 1G (copper SFPs) | TAP legs |
| EXA P5 | laptop NIC 1 | 1G (copper SFP) | tool port |
| EXA P6 | laptop NIC 2 | 1G (copper SFP) | ingress copy (optional) |

**Switch: Cisco Catalyst C9300-24T-E** (24 x 1G copper, Network Essentials). Its 10G port Te1/1/1 comes from a
**C9300-NM-8X** network module (8 x 10G SFP+) with a 10G SFP+ to the EXA. ERSPAN (test L08) also needs a
**Cisco DNA licence** (for example C9300-DNA-E-24-3Y): check with `show license summary`. Without the module or the
licence, run every other test and skip L08.

### Optional: optical TAP on a 10G link (better L05 and L09)

With a 10G multimode link in the lab, for example 9300 Te1/1/2 to a lab server with a 10GBASE-SR NIC, put the
optical TAP on it and connect its monitor outputs to two spare EXA ports with 10GBASE-SR optics (P7, P8). Then:
- **L05 (burst):** real bursts of several Gbps on one link (iperf3 to the 10G server) into the 1G tool port P5,
  instead of using both directions at once on the 1G link.
- **L09 (jumbo):** the passive TAP passes jumbo frames for certain.

For these tests, set rule "tool" to inputs P7 + P8 (and rule "ingress" too, for proving fixes).

### Optional: OptoSlim multi-link TAP (L13, L14)

**CUB.OPTOSLIM-4L-MM / -8L-MM:** passive, 4 or 8 multimode links (50/125 µm, 850/1300 nm) in a 1/3 RU chassis,
LC duplex connectors, 50/50 split as standard (the -7 versions are 70/30), 10 Mbps to 100 Gbps, typical insertion
loss 3.8 dB. Each tapped link uses two EXA input ports (one per direction) with matching SR optics, so 4 links need
8 EXA ports: the EXA48800 has plenty.

Two realistic tests it makes possible:
- **L13, many links into one tool:** tap 2-4 busy fibre links and aggregate all of them in one EXA rule to the 1G
  tool port P5. Their combined load overflows it: the classic real-world tool overload. VisiLoop should report tool
  overload and size a tool group.
- **L14, the same traffic tapped twice:** tap two links that the same traffic crosses (for example a server's
  uplink and the switch-to-switch link behind it) and aggregate both in one EXA rule with deduplication off. Every
  packet arrives twice: the most common real cause of duplicates, with no SPAN involved. Turning EXA
  deduplication on is VisiLoop's fix.

**Traffic:** rate-limit the standard 50 MB download (`curl --limit-rate 25M ...`). At full 1G speed it fills the
1G tool port above VisiLoop's 80% burst limit, so every test would also report tool overload.

## Baseline (start of the session, and between tests)

**EXA48800:**
- P5 and P6 set to 1G with copper SFPs.
- Rule "tool": inputs P1 + P2, output P5. No slicing, no deduplication, no VLAN change, no tunnel handling.
- Rule "ingress" (optional): inputs P1 + P2, output P6, no changes. This is the lossless copy VisiLoop uses to
  prove its fixes on real traffic.
- SNMP v2c read-only, allowed only from the laptop's IP.

**Catalyst 9300:**
```
configure terminal
 interface range Gi1/0/1 - 2
  switchport mode access
  switchport access vlan 1
 ip access-list standard VISILOOP
  permit <laptop IP>
 snmp-server community visiloop-ro RO VISILOOP
end
```

**Check from the laptop:**
```
python -m visikit.counters --list <9300 mgmt IP> --community visiloop-ro
python -m visikit.counters --list <EXA mgmt IP> --community visiloop-ro
```
Copy the exact interface names into `lab/lab_path.yaml` (the 9300 usually reports short names such as `Gi1/0/24`).

## Test by test

| Test | Change | 9300 commands / EXA setting | Undo |
|---|---|---|---|
| L01 baseline | none | baseline above | - |
| L02 RX-only SPAN | tool fed by a SPAN that copies received traffic only | 9300: `monitor session 1 source interface Gi1/0/1 rx` and `monitor session 1 destination interface Gi1/0/24`. EXA rule "tool": input P3 only (instead of P1 + P2); rule "ingress" unchanged | `no monitor session 1`; rule "tool" back to P1 + P2 |
| L03 duplicates | TAP and SPAN of the same link on one tool port | 9300: `monitor session 1 source interface Gi1/0/1 both`, destination Gi1/0/24. EXA rule "tool": inputs P1 + P2 + P3, **deduplication off** | `no monitor session 1`; rule back to P1 + P2 |
| L04 SPAN overloaded | more mirrored than a 1G destination can send | 9300: `monitor session 1 source interface Gi1/0/1 - 2 both`, destination Gi1/0/24. EXA rule "tool": input P3. Run iperf3 at about 900 Mbit/s (`iperf3 -c <server> -t 90 -b 900M`): both directions mirrored exceed 1G. Expect missing data and tool overload (Gi1/0/24 fills the 1G tool port) | `no monitor session 1`; rule back |
| L05 burst | bursts above the tool port speed | Baseline. Needs more than 1 Gbps on the TAP legs together: run iperf3 in both directions at once (`iperf3 -c <server> -t 60 --bidir`). The EXA's 1G P5 then overflows: expect tool overload and missing data | stop iperf3 |
| L06 VLAN stripped | tags removed before the tool | EXA: tag traffic arriving on P1 with VLAN 10 and on P2 with VLAN 20 (per-port VLAN tagging), then **VLAN stripping on** for output P5. Plan VLANs: 10, 20 | stripping off; tagging off |
| L07 slicing | packets cut to 128 bytes | EXA rule "tool": **slicing 128 bytes** on P5 | slicing off |
| L08 tunnel | ERSPAN delivered still wrapped | 9300 ERSPAN source (below) to the EXA's tunnel endpoint on P4. EXA: terminate the ERSPAN session on P4, **header stripping off**, output P5; rule "tool" input P4 only | `no monitor session 2`; rule back |
| L09 jumbo | frames above 1518 bytes | 9300: `system mtu 9198`. MTU 9000 on the lab client and server NICs. Baseline rule. Then `iperf3 -c <server> -t 30 -b 200M` (full speed would also fill the tool port) | hosts back to MTU 1500 (switch MTU can stay) |
| L10 encrypted | HTTPS only | baseline; HTTPS downloads only | - |
| L11 combined | RX-only SPAN and slicing | L02 setup plus slicing 128 bytes on P5; add an upload (`iperf3 -c <server> -t 30 -b 50M`) | undo both |
| L12 SIEM tolerates slicing | slicing, judged as a SIEM | L07 setup | slicing off |

**ERSPAN source on the 9300 (L08):**
```
configure terminal
 interface Te1/1/1
  no switchport
  ip address 192.168.250.1 255.255.255.252
 monitor session 2 type erspan-source
  source interface Gi1/0/1 both
  no shutdown
  destination
   erspan-id 10
   ip address 192.168.250.2
   origin ip address 192.168.250.1
end
```
On the EXA, give P4 the address 192.168.250.2 as its GRE/ERSPAN endpoint. Check that the session is up with
`show monitor session 2` and `show platform software fed switch active monitor 2`.

**L08b, the fix:** with the same session, turn ERSPAN header stripping **on** in the EXA. The plan records this
as test L08b, which VisiLoop should report healthy: its own recommended fix, verified on real equipment.

## Counters during the tests

`lab/lab_path.yaml` follows the SPAN path (Gi1/0/1 → Gi1/0/24 → EXA P3 → EXA P5). Run
`python -m visikit.monitor --config lab/lab_monitor.yaml` in a second window during L04 and L05: it should name
`Gi1/0/24` (L04) and EXA P5 (L05) as where packets are lost.
