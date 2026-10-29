"""A tiny SNMP v2c agent that serves interface counters from a JSON file, for testing the reader.

    python tests/fake_snmp_agent.py counters.json --port 1161 --community npb

counters.json: {"1": {"name": "1/1", "in_pkts": ..., "out_pkts": ..., "in_octets": ..., "out_octets": ...,
                      "in_discards": 0, "out_discards": 0, "in_errors": 0, "speed_mbps": 1000}, ...}
The file is re-read on every request, so a test can change the counters while the agent runs.
"""
import argparse
import json

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto.api import v2c
from pysnmp.smi import instrum

IFX, IF = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1), (1, 3, 6, 1, 2, 1, 2, 2, 1)


def table(path):
    with open(path) as f:
        data = json.load(f)
    rows = {}
    for idx, c in data.items():
        i = int(idx)
        rows[IFX + (1, i)] = v2c.OctetString(c["name"])
        rows[IFX + (6, i)] = v2c.Counter64(c["in_octets"])
        rows[IFX + (7, i)] = v2c.Counter64(c["in_pkts"])
        rows[IFX + (8, i)] = v2c.Counter64(0)
        rows[IFX + (9, i)] = v2c.Counter64(0)
        rows[IFX + (10, i)] = v2c.Counter64(c["out_octets"])
        rows[IFX + (11, i)] = v2c.Counter64(c["out_pkts"])
        rows[IFX + (12, i)] = v2c.Counter64(0)
        rows[IFX + (13, i)] = v2c.Counter64(0)
        rows[IFX + (15, i)] = v2c.Gauge32(c.get("speed_mbps", 1000))
        rows[IF + (13, i)] = v2c.Counter32(c.get("in_discards", 0))
        rows[IF + (14, i)] = v2c.Counter32(c.get("in_errors", 0))
        rows[IF + (19, i)] = v2c.Counter32(c.get("out_discards", 0))
    return dict(sorted(rows.items()))


class Instrumentation(instrum.AbstractMibInstrumController):
    def __init__(self, path):
        self.path = path

    def read_variables(self, *var_binds, **ctx):
        rows = table(self.path)
        return [(oid, rows.get(tuple(oid), v2c.NoSuchInstance())) for oid, _ in var_binds]

    def read_next_variables(self, *var_binds, **ctx):
        rows = table(self.path)
        out = []
        for oid, _ in var_binds:
            nxt = next(((k, v) for k, v in rows.items() if k > tuple(oid)), None)
            out.append((v2c.ObjectIdentifier(nxt[0]), nxt[1]) if nxt else (oid, v2c.EndOfMibView()))
        return out

    def write_variables(self, *var_binds, **ctx):
        raise NotImplementedError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("counters")
    ap.add_argument("--port", type=int, default=1161)
    ap.add_argument("--community", default="public")
    a = ap.parse_args()
    eng = engine.SnmpEngine()
    config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", a.port)))
    config.add_v1_system(eng, "agent", a.community)
    config.add_vacm_user(eng, 2, "agent", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
    ctx = context.SnmpContext(eng)
    ctx.unregister_context_name(v2c.OctetString(b""))
    ctx.register_context_name(v2c.OctetString(b""), Instrumentation(a.counters))
    cmdrsp.GetCommandResponder(eng, ctx)
    cmdrsp.NextCommandResponder(eng, ctx)
    cmdrsp.BulkCommandResponder(eng, ctx)
    eng.transport_dispatcher.job_started(1)
    print(f"fake SNMP agent on 127.0.0.1:{a.port}, community {a.community}", flush=True)
    eng.open_dispatcher()


if __name__ == "__main__":
    main()
