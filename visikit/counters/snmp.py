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
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, UdpTransportTarget
        engine = SnmpEngine()
        out = {}
        for h in self.hops:
            src = h.source or {}
            if not src.get("host"):
                continue                                  # passive TAPs and hops without counters
            target = await UdpTransportTarget.create((src["host"], int(src.get("port", 161))),
                                                     timeout=self.timeout, retries=self.retries)
            community = src.get("community", "public")
            key = (src["host"], src.get("if_name"), src.get("if_index"))
            if key not in self._index:
                self._index[key] = int(src["if_index"]) if src.get("if_index") else \
                    await _if_index(engine, target, community, src["if_name"])
            i = self._index[key]
            names = list(OIDS)
            vals = dict(zip(names, await _get(engine, target, community, [f"{OIDS[n]}.{i}" for n in names])))
            out[h.name] = Snapshot(
                in_pkts=vals["in_ucast"] + vals["in_mcast"] + vals["in_bcast"],
                out_pkts=vals["out_ucast"] + vals["out_mcast"] + vals["out_bcast"],
                in_octets=vals["in_octets"], out_octets=vals["out_octets"],
                in_discards=vals["in_discards"], out_discards=vals["out_discards"], in_errors=vals["in_errors"],
                speed_gbps=vals["high_speed"] / 1000)
        engine.close_dispatcher()
        return out

    def snapshot(self):
        return asyncio.run(self._read_all())

    def measure(self, seconds=60):
        import time
        before = self.snapshot()
        t0 = time.time()
        time.sleep(seconds)
        after = self.snapshot()
        return PathCounters(self.hops, before, after, time.time() - t0)
