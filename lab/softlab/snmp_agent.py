"""SNMP v2c agent (read-only IF-MIB counters) running inside a soft-lab daemon, on its management address.

Answers from the daemon's live counters at the moment of each request, as a real switch or broker does.
"""
import asyncio
import threading

IFX, IF = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1), (1, 3, 6, 1, 2, 1, 2, 2, 1)


def _table(rows):
    from pysnmp.proto.api import v2c
    out = {}
    for idx, c in rows.items():
        i = int(idx)
        out[IFX + (1, i)] = v2c.OctetString(c["name"])
        out[IFX + (6, i)] = v2c.Counter64(c["in_octets"])
        out[IFX + (7, i)] = v2c.Counter64(c["in_pkts"])
        out[IFX + (8, i)] = v2c.Counter64(0)
        out[IFX + (9, i)] = v2c.Counter64(0)
        out[IFX + (10, i)] = v2c.Counter64(c["out_octets"])
        out[IFX + (11, i)] = v2c.Counter64(c["out_pkts"])
        out[IFX + (12, i)] = v2c.Counter64(0)
        out[IFX + (13, i)] = v2c.Counter64(0)
        out[IFX + (15, i)] = v2c.Gauge32(int(c.get("speed_mbps", 1000)))
        out[IFX + (18, i)] = v2c.OctetString(c.get("alias", ""))
        out[IF + (13, i)] = v2c.Counter32(c.get("in_discards", 0) & 0xFFFFFFFF)
        out[IF + (14, i)] = v2c.Counter32(c.get("in_errors", 0) & 0xFFFFFFFF)
        out[IF + (19, i)] = v2c.Counter32(c.get("out_discards", 0) & 0xFFFFFFFF)
    return dict(sorted(out.items()))


def serve(host, port, community, rows_fn):
    """Start the agent in a background thread. rows_fn() returns {ifIndex: {name, in_octets, ...}}."""
    def run():
        asyncio.set_event_loop(asyncio.new_event_loop())
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.entity import config, engine
        from pysnmp.entity.rfc3413 import cmdrsp, context
        from pysnmp.proto.api import v2c
        from pysnmp.smi import instrum

        class Instrumentation(instrum.AbstractMibInstrumController):
            def read_variables(self, *var_binds, **ctx):
                rows = _table(rows_fn())
                return [(oid, rows.get(tuple(oid), v2c.NoSuchInstance())) for oid, _ in var_binds]

            def read_next_variables(self, *var_binds, **ctx):
                rows = _table(rows_fn())
                out = []
                for oid, _ in var_binds:
                    nxt = next(((k, v) for k, v in rows.items() if k > tuple(oid)), None)
                    out.append((v2c.ObjectIdentifier(nxt[0]), nxt[1]) if nxt else (oid, v2c.EndOfMibView()))
                return out

            def write_variables(self, *var_binds, **ctx):
                raise NotImplementedError

        eng = engine.SnmpEngine()
        config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((host, port)))
        config.add_v1_system(eng, "agent", community)
        config.add_vacm_user(eng, 2, "agent", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
        ctx = context.SnmpContext(eng)
        ctx.unregister_context_name(v2c.OctetString(b""))
        ctx.register_context_name(v2c.OctetString(b""), Instrumentation())
        cmdrsp.GetCommandResponder(eng, ctx)
        cmdrsp.NextCommandResponder(eng, ctx)
        cmdrsp.BulkCommandResponder(eng, ctx)
        eng.transport_dispatcher.job_started(1)
        eng.open_dispatcher()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
