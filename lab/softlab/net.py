"""Build and remove the soft lab's virtual network (Linux network namespaces and veth pairs).

    vl-client eth0 ── gi1 ┐                      ┌ gi2 ── eth0 vl-server
                          └──── br0 (vl-switch) ─┘
    vl-switch: tapa ─ p1, tapb ─ p2 (TAP legs), gi24 ─ p3 (SPAN), te1 ─ p4 (ERSPAN)   [vl-broker]
    vl-broker: p5 ─ nic1 (tool feed), p6 ─ nic2 (lossless copy)                         [vl-tool]

Management: the switch answers SNMP on 172.30.0.2 and the broker on 172.30.0.6, reached from
the host (where VisiLoop runs) over vl-msw (172.30.0.1) and vl-mnpb (172.30.0.5).

The client and server links are shaped to 25 Mbit/s (Linux tbf), the access speed of this lab.
Needs root (Linux, or WSL 2 on Windows) and iproute2 + ethtool.
"""
import subprocess

NS = ["vl-client", "vl-server", "vl-switch", "vl-broker", "vl-tool"]
LINKS = [("vl-client", "eth0", "vl-switch", "gi1"), ("vl-server", "eth0", "vl-switch", "gi2"),
         ("vl-switch", "tapa", "vl-broker", "p1"), ("vl-switch", "tapb", "vl-broker", "p2"),
         ("vl-switch", "gi24", "vl-broker", "p3"), ("vl-switch", "te1", "vl-broker", "p4"),
         ("vl-broker", "p5", "vl-tool", "nic1"), ("vl-broker", "p6", "vl-tool", "nic2")]
CLIENT, SERVER = "10.10.0.1", "10.10.0.2"
MGMT = [("vl-msw", "172.30.0.1", "vl-switch", "172.30.0.2"), ("vl-mnpb", "172.30.0.5", "vl-broker", "172.30.0.6")]
SWITCH_MGMT, BROKER_MGMT = "172.30.0.2", "172.30.0.6"
ACCESS_MBIT = 25
OFFLOADS = ["tso", "gso", "gro", "tx", "rx", "rxvlan", "txvlan"]


def sh(*args, check=True):
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def nsx(ns, *args, check=True):
    return sh("ip", "netns", "exec", ns, *args, check=check)


def shape(mtu):
    """Access-link shaping on both hosts; the burst allows one full frame, so bursts stay realistic."""
    burst = max(1600, mtu + 200)
    for ns in ("vl-client", "vl-server"):
        nsx(ns, "tc", "qdisc", "replace", "dev", "eth0", "root", "tbf", "rate", f"{ACCESS_MBIT}mbit",
            "burst", str(burst), "latency", "50ms")


def set_host_mtu(mtu):
    for ns in ("vl-client", "vl-server"):
        nsx(ns, "ip", "link", "set", "eth0", "mtu", str(mtu))
    shape(mtu)


def up():
    down()
    for ns in NS:
        sh("ip", "netns", "add", ns)
        nsx(ns, "ip", "link", "set", "lo", "up")
    for a_ns, a, b_ns, b in LINKS:
        sh("ip", "link", "add", a, "netns", a_ns, "type", "veth", "peer", "name", b, "netns", b_ns)
        for ns, dev in ((a_ns, a), (b_ns, b)):
            nsx(ns, "ip", "link", "set", dev, "mtu", "9216")
            nsx(ns, "ethtool", "-K", dev, *[x for o in OFFLOADS for x in (o, "off")], check=False)
            nsx(ns, "ip", "link", "set", dev, "up")
    nsx("vl-switch", "ip", "link", "add", "br0", "type", "bridge")
    nsx("vl-switch", "ip", "link", "set", "br0", "mtu", "9216")
    for dev in ("gi1", "gi2"):
        nsx("vl-switch", "ip", "link", "set", dev, "master", "br0")
    nsx("vl-switch", "ip", "link", "set", "br0", "up")
    nsx("vl-client", "ip", "addr", "add", f"{CLIENT}/24", "dev", "eth0")
    nsx("vl-server", "ip", "addr", "add", f"{SERVER}/24", "dev", "eth0")
    for host_if, host_ip, ns, ns_ip in MGMT:
        sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", "mgmt0", "netns", ns)
        sh("ip", "addr", "add", f"{host_ip}/30", "dev", host_if)
        sh("ip", "link", "set", host_if, "up")
        nsx(ns, "ip", "addr", "add", f"{ns_ip}/30", "dev", "mgmt0")
        nsx(ns, "ip", "link", "set", "mgmt0", "up")
    set_host_mtu(1500)


def down():
    for ns in NS:
        sh("ip", "netns", "del", ns, check=False)
    for host_if, *_ in MGMT:
        sh("ip", "link", "del", host_if, check=False)


if __name__ == "__main__":
    import sys
    {"up": up, "down": down}[sys.argv[1]]()
