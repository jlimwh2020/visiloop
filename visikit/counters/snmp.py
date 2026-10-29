"""Read interface counters from switches and brokers over SNMP (IF-MIB).

Virtually every switch and packet broker supports these standard counters. Each hop says
how to reach it, in the path file:

    - name: "NPB-01 port 5 (to IDS)"
      role: broker_out
      device: NPB-01
      port: "5"
      speed_gbps: 1
      source: {host: 192.0.2.10, community: public, if_name: "1/5"}     # or if_index: 5

SNMP v2c with a read-only community. Use a monitoring network and an access list that only
allows the VisiLoop host. Numeric OIDs are used, so no MIB files are needed.

Usage:
    python -m visikit.counters --path demo/counters/snmp_example.yaml --seconds 60
"""
import asyncio
import time

from visikit.counters import PathCounters, Snapshot

IFX = "1.3.6.1.2.1.31.1.1.1"     # ifXTable (64-bit counters)
IF = "1.3.6.1.2.1.2.2.1"         # ifTable
OIDS = {
    "in_octets": f"{IFX}.6", "out_octets": f"{IFX}.10",
    "in_ucast": f"{IFX}.7", "in_mcast": f"{IFX}.8", "in_bcast": f"{IFX}.9",
    "out_ucast": f"{IFX}.11", "out_mcast": f"{IFX}.12", "out_bcast": f"{IFX}.13",
    "high_speed": f"{IFX}.15",                       # Mbps
    "in_discards": f"{IF}.13", "in_errors": f"{IF}.14", "out_discards": f"{IF}.19",
}
IF_NAME = f"{IFX}.1"


async def _get(engine, target, community, oids):
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData, ObjectIdentity, ObjectType, get_cmd
    err, status, idx, binds = await get_cmd(engine, CommunityData(community, mpModel=1), target, ContextData(),
                                            *[ObjectType(ObjectIdentity(o)) for o in oids])
    if err or status:
        raise RuntimeError(f"SNMP error: {err or status.prettyPrint()}")
    return [int(v) if v.__class__.__name__ not in ("NoSuchInstance", "NoSuchObject", "EndOfMibView") else 0
            for _, v in binds]


async def _if_index(engine, target, community, name):
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData, ObjectIdentity, ObjectType, walk_cmd
    async for err, status, idx, binds in walk_cmd(engine, CommunityData(community, mpModel=1), target, ContextData(),
                                                  ObjectType(ObjectIdentity(IF_NAME)), lexicographicMode=False):
        if err or status:
            raise RuntimeError(f"SNMP error: {err or status.prettyPrint()}")
        for oid, val in binds:
            if str(val) == name:
                return int(str(oid).rsplit(".", 1)[1])
    raise LookupError(f"interface {name!r} not found")


async def _list(host, community, port=161, timeout=2, retries=1):
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
                                             UdpTransportTarget, walk_cmd)
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((host, int(port)), timeout=timeout, retries=retries)
    rows = {}
    for col, key in ((IF_NAME, "name"), (OIDS["high_speed"], "mbps"), ("1.3.6.1.2.1.31.1.1.1.18", "alias")):
        async for err, status, idx, binds in walk_cmd(engine, CommunityData(community, mpModel=1), target, ContextData(),
                                                      ObjectType(ObjectIdentity(col)), lexicographicMode=False):
            if err or status:
                raise RuntimeError(f"SNMP error: {err or status.prettyPrint()}")
            for oid, val in binds:
                i = int(str(oid).rsplit(".", 1)[1])
                rows.setdefault(i, {})[key] = str(val)
    engine.close_dispatcher()
    return rows


def list_interfaces(host, community, port=161):
    """Every interface a device reports: index, name, speed and description, for writing a path file."""
    return asyncio.run(_list(host, community, port))


class SnmpSource:
    def __init__(self, hops, timeout=2, retries=1):
        self.hops = hops
        self.timeout, self.retries = timeout, retries
        self._index = {}

    async def _read_all(self):
        """Read every hop: one SNMP request per device for all of its interfaces, all devices at once, so the
        readings along a path are taken as close together in time as possible (see counters.skew_allowance)."""
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, UdpTransportTarget
        engine = SnmpEngine()
        devices = {}
        for h in self.hops:
            src = h.source or {}
            if src.get("host"):                           # passive TAPs and hops without counters are skipped
                key = (src["host"], int(src.get("port", 161)), src.get("community", "public"))
                devices.setdefault(key, []).append(h)

        # First connect to every device and find its interface numbers; then send all the counter requests at
        # once. A device samples its counters as it answers, and the answer arrives within milliseconds, so the
        # time it arrives is when the counters were read.
        ready = []
        for (host, port, community), hops in devices.items():
            target = await UdpTransportTarget.create((host, port), timeout=self.timeout, retries=self.retries)
            idx = []
            for h in hops:
                ik = (host, h.source.get("if_name"), h.source.get("if_index"))
                if ik not in self._index:
                    self._index[ik] = int(h.source["if_index"]) if h.source.get("if_index") else \
                        await _if_index(engine, target, community, h.source["if_name"])
                idx.append(self._index[ik])
            ready.append((target, community, hops, idx))
        names = list(OIDS)

        async def read_device(target, community, hops, idx):
            vals = await _get(engine, target, community, [f"{OIDS[n]}.{i}" for i in idx for n in names])
            at = time.time()
            out = {}
            for k, h in enumerate(hops):
                v = dict(zip(names, vals[k * len(names):(k + 1) * len(names)]))
                out[h.name] = Snapshot(
                    in_pkts=v["in_ucast"] + v["in_mcast"] + v["in_bcast"],
                    out_pkts=v["out_ucast"] + v["out_mcast"] + v["out_bcast"],
                    in_octets=v["in_octets"], out_octets=v["out_octets"],
                    in_discards=v["in_discards"], out_discards=v["out_discards"], in_errors=v["in_errors"],
                    speed_gbps=v["high_speed"] / 1000, at=at)
            return out

        results = await asyncio.gather(*(read_device(*r) for r in ready))
        engine.close_dispatcher()
        return {name: snap for r in results for name, snap in r.items()}

    def snapshot(self):
        return asyncio.run(self._read_all())

    def measure(self, seconds=60):
        import time
        before = self.snapshot()
        t0 = time.time()
        time.sleep(seconds)
        after = self.snapshot()
        return PathCounters(self.hops, before, after, time.time() - t0)
