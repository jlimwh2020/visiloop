"""Simulated interface counters for a feed's path: for tests, demos and continuous-mode trials.

A scenario (YAML) gives the path, the traffic and faults that start at a given time:

    feed: ids-1
    traffic: {gbps: 0.6, avg_packet_bytes: 700}
    path:
      - {name: CORE-SW-01 Gi1/0/1 (mirrored), role: span_source, device: CORE-SW-01, port: Gi1/0/1, speed_gbps: 10, mirrors: both}
      - {name: CORE-SW-01 Gi1/0/48 (SPAN destination), role: span_dest, device: CORE-SW-01, port: Gi1/0/48, speed_gbps: 1}
      - {name: NPB-01 port 1 (input), role: broker_in, device: NPB-01, port: "1", speed_gbps: 1}
      - {name: NPB-01 port 5 (to IDS), role: broker_out, device: NPB-01, port: "5", speed_gbps: 1}
    events:
      - {at: 120, kind: surge, gbps: 1.6}                       # traffic grows
      - {at: 300, kind: crc_errors, hop: NPB-01 port 1 (input), rate: 0.0005}

Event kinds: surge (total mirrored traffic), crc_errors / nic_overrun (rate of packets at a hop),
link_loss (rate lost between a hop and the next one). Discards at an egress port follow
automatically when the offered load exceeds its speed.
"""
import yaml

from visikit.counters import Hop, PathCounters, Snapshot


class Simulator:
    def __init__(self, scenario):
        if isinstance(scenario, str):
            with open(scenario) as f:
                scenario = yaml.safe_load(f)
        self.sc = scenario
        self.feed = scenario.get("feed", "feed-1")
        self.hops = [Hop(**{k: v for k, v in h.items() if k in Hop.__dataclass_fields__}) for h in scenario["path"]]
        self.events = sorted(scenario.get("events", []), key=lambda e: e["at"])
        self.state = {h.name: Snapshot(speed_gbps=h.speed_gbps) for h in self.hops}
        self.t = 0.0

    def _at(self, t, kind, hop=None):
        """Latest event of this kind (and hop) that has started by time t."""
        ev = [e for e in self.events if e["kind"] == kind and e["at"] <= t and (hop is None or e.get("hop") == hop)]
        return ev[-1] if ev else None

    def advance(self, seconds):
        """Move time forward, adding the traffic of `seconds` (in 1-second steps) to every counter."""
        for _ in range(int(seconds)):
            self._step(1.0)
        return self

    def _step(self, dt):
        t = self.t
        surge = self._at(t, "surge")
        gbps = surge["gbps"] if surge else self.sc["traffic"]["gbps"]
        size = self.sc["traffic"].get("avg_packet_bytes", 700)
        bits = gbps * 1e9 * dt
        pkts = bits / 8 / size
        carried_pkts, carried_bytes = pkts, bits / 8          # what reaches the next hop
        for i, h in enumerate(self.hops):
            s = self.state[h.name]
            if h.role == "tap":
                continue
            if h.role == "span_source":
                share = {"both": 0.5, "rx": 1.0, "tx": 1.0}.get(h.mirrors, 0.5)
                s.in_pkts += int(pkts * share)
                s.out_pkts += int(pkts * (1 - share)) if h.mirrors == "both" else 0
                s.in_octets += int(bits / 8 * share)
                s.out_octets += int(bits / 8 * (1 - share)) if h.mirrors == "both" else 0
                continue
            # receive
            if h.role in ("broker_in", "tool_in"):
                errs = self._at(t, "crc_errors", h.name)
                over = self._at(t, "nic_overrun", h.name)
                err = carried_pkts * errs["rate"] if errs else 0
                disc = carried_pkts * over["rate"] if over else 0
                s.in_errors += int(err)
                s.in_discards += int(disc)
                s.in_pkts += int(carried_pkts - err - disc)
                s.in_octets += int(carried_bytes * (1 - (err + disc) / max(carried_pkts, 1)))
                carried_pkts -= err + disc
                carried_bytes *= 1 - (err + disc) / max(carried_pkts + err + disc, 1)
            # send: an egress port cannot send more than its speed; the rest is discarded
            if h.role in ("span_dest", "broker_out"):
                cap_bytes = h.speed_gbps * 1e9 / 8 * dt if h.speed_gbps else carried_bytes
                sent_bytes = min(carried_bytes, cap_bytes)
                sent_pkts = carried_pkts * (sent_bytes / carried_bytes) if carried_bytes else 0
                s.out_discards += int(carried_pkts - sent_pkts)
                s.out_pkts += int(sent_pkts)
                s.out_octets += int(sent_bytes)
                carried_pkts, carried_bytes = sent_pkts, sent_bytes
                loss = self._at(t, "link_loss", h.name)
                if loss:
                    carried_pkts *= 1 - loss["rate"]
                    carried_bytes *= 1 - loss["rate"]
        self.t += dt

    def snapshot(self):
        return {k: Snapshot(**vars(v)) for k, v in self.state.items()}

    def measure(self, seconds=60):
        """Two readings `seconds` apart, as a PathCounters for the checks."""
        before = self.snapshot()
        self.advance(seconds)
        return PathCounters(self.hops, before, self.snapshot(), seconds)
