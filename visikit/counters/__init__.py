"""Interface counters along a monitoring feed's path.

A feed's path is a list of hops, from where traffic is copied to the tool:

    span_source  a switch port being mirrored (counts what the SPAN session should copy)
    span_dest    the switch port sending SPAN copies to the broker
    tap          a passive TAP (no counters; listed so the path reads naturally)
    broker_in    the broker port receiving the copies
    broker_out   the broker tool port
    tool_in      the security tool's capture interface (if its counters can be read)

Counters are the standard interface counters every switch and broker exposes (IF-MIB over
SNMP, or a vendor API): packets and bytes in and out, discards, errors and port speed.
Two readings some seconds apart give the traffic in between; comparing neighbouring hops
shows where packets are lost.

Sources: `simulator.Simulator` (scenarios for tests and demos) and `snmp.SnmpSource`.
"""
from dataclasses import dataclass, field


@dataclass
class Hop:
    name: str                        # e.g. "CORE-SW-01 Gi1/0/48 (SPAN destination)"
    role: str                        # span_source | span_dest | tap | broker_in | broker_out | tool_in
    device: str = ""                 # device name, as on the diagram
    port: str = ""
    speed_gbps: float = 0.0
    mirrors: str = "both"            # span_source only: both | rx | tx
    source: dict = field(default_factory=dict)   # how to read it (e.g. SNMP host, community, interface)


@dataclass
class Snapshot:
    """Cumulative interface counters at one moment."""
    in_pkts: int = 0
    out_pkts: int = 0
    in_octets: int = 0
    out_octets: int = 0
    in_discards: int = 0
    out_discards: int = 0
    in_errors: int = 0
    speed_gbps: float = 0.0


@dataclass
class PathCounters:
    """Two readings of every hop on a feed's path, `seconds` apart."""
    hops: list
    before: dict                     # hop name -> Snapshot
    after: dict
    seconds: float

    def delta(self, hop):
        a, b = self.before.get(hop.name), self.after.get(hop.name)
        if a is None or b is None:
            return None
        d = Snapshot(**{k: getattr(b, k) - getattr(a, k) for k in vars(a) if k != "speed_gbps"})
        d.speed_gbps = hop.speed_gbps or b.speed_gbps
        return d

    def gbps(self, octets):
        return octets * 8 / self.seconds / 1e9 if self.seconds else 0.0


def analyse(pc: PathCounters, loss_threshold=0.001, util_threshold=0.8):
    """Locate loss and errors along the path. Returns a list of issue dicts, worst first."""
    issues = []
    hops = [h for h in pc.hops if h.role != "tap"]
    d = {h.name: pc.delta(h) for h in hops}

    def add(kind, hop, lost, of, detail, **extra):
        share = lost / of if of else 0.0
        if lost > 0 and share > loss_threshold:
            issues.append({"kind": kind, "hop": hop.name, "role": hop.role, "device": hop.device, "port": hop.port,
                           "lost": int(lost), "of": int(of), "share": round(share, 5), "detail": detail, **extra})

    for i, h in enumerate(hops):
        x = d[h.name]
        if x is None:
            continue
        nxt = hops[i + 1] if i + 1 < len(hops) else None
        y = d.get(nxt.name) if nxt else None
        if h.role == "span_source":
            offered = {"both": x.in_pkts + x.out_pkts, "rx": x.in_pkts, "tx": x.out_pkts}.get(h.mirrors, x.in_pkts + x.out_pkts)
            offered_octets = {"both": x.in_octets + x.out_octets, "rx": x.in_octets, "tx": x.out_octets}.get(h.mirrors)
            if nxt is not None and nxt.role == "span_dest" and y is not None:
                lost = offered - y.out_pkts
                dest_gbps = pc.gbps(offered_octets or 0)
                add("span_oversubscribed", nxt, lost, offered,
                    f"the SPAN session should copy {offered:,} packets from {h.name} but {nxt.name} sent only "
                    f"{y.out_pkts:,}: {dest_gbps:.2f} Gbps mirrored into a {nxt.speed_gbps or y.speed_gbps:g} Gbps "
                    "destination port", offered_gbps=round(dest_gbps, 3))
            continue
        # drops counted by the device itself
        if h.role in ("span_dest", "broker_out"):
            util = pc.gbps(x.out_octets) / x.speed_gbps if x.speed_gbps else 0
            # Offered load = what was sent plus what was discarded (discards are counted in packets,
            # so scale the sent bytes by the packet ratio)
            offered = pc.gbps(x.out_octets) * (x.out_pkts + x.out_discards) / x.out_pkts if x.out_pkts else 0
            add("egress_discards", h, x.out_discards, x.out_pkts + x.out_discards,
                f"{h.name} discarded {x.out_discards:,} packets on output: about {offered:.2f} Gbps offered to a "
                f"{x.speed_gbps:g} Gbps port (average load {util:.0%}; bursts are higher)",
                offered_gbps=round(offered, 3), speed_gbps=x.speed_gbps)
        if h.role in ("broker_in", "tool_in"):
            add("ingress_discards", h, x.in_discards, x.in_pkts + x.in_discards,
                f"{h.name} discarded {x.in_discards:,} packets it received"
                + (" (the tool's capture interface could not keep up)" if h.role == "tool_in" else ""))
            if x.in_errors:
                issues.append({"kind": "link_errors", "hop": h.name, "role": h.role, "device": h.device, "port": h.port,
                               "lost": x.in_errors, "of": x.in_pkts + x.in_errors,
                               "share": round(x.in_errors / max(1, x.in_pkts + x.in_errors), 6),
                               "detail": f"{h.name} received {x.in_errors:,} damaged frames (CRC/alignment errors): "
                                         "a faulty cable, optic or duplex mismatch on the link into it"})
        # packets that leave one hop but never arrive at the next: the link between them
        if y is not None and h.role in ("span_dest", "broker_out") and nxt.role in ("broker_in", "tool_in"):
            add("link_loss", nxt, x.out_pkts - y.in_pkts - y.in_discards - y.in_errors, x.out_pkts,
                f"{h.name} sent {x.out_pkts:,} packets but {nxt.name} saw only {y.in_pkts + y.in_discards + y.in_errors:,}: "
                "lost on the link between them (cable, optic or an unmonitored device)")
    issues.sort(key=lambda i: -i["share"])
    return issues
