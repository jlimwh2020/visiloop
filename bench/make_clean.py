"""Generate a synthetic, healthy monitoring-feed capture with known properties.

Clients sit on VLAN 10 (10.10.10.0/24), servers on VLAN 20 (10.20.20.0/24).
Every TCP session is complete in both directions, with correct sequence numbers.
"""
import argparse
import random

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Dot1Q, Ether, wrpcap

CLIENT_MAC, SERVER_MAC = "00:00:00:00:10:01", "00:00:00:00:20:01"


def _l2(src_is_client, vlans):
    if not vlans:
        return Ether(src=CLIENT_MAC, dst=SERVER_MAC) if src_is_client else Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    vid = 10 if src_is_client else 20
    eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC) if src_is_client else Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    return eth / Dot1Q(vlan=vid)


def _tls_payload(rng, size):
    body = bytes(rng.getrandbits(8) for _ in range(size - 5))
    return b"\x17\x03\x03" + len(body).to_bytes(2, "big") + body


def tcp_session(rng, t, cip, sip, cport, tls, vlans):
    """Return a list of (time, packet) for one complete TCP session."""
    sport = 443 if tls else 80
    out, c_seq, s_seq = [], rng.randint(1, 2**31), rng.randint(1, 2**31)

    def send(from_client, flags, payload=b""):
        nonlocal t, c_seq, s_seq
        t += rng.uniform(0.0002, 0.002)
        if from_client:
            ip = IP(src=cip, dst=sip) / TCP(sport=cport, dport=sport, flags=flags, seq=c_seq, ack=s_seq if "A" in flags else 0)
        else:
            ip = IP(src=sip, dst=cip) / TCP(sport=sport, dport=cport, flags=flags, seq=s_seq, ack=c_seq)
        pkt = _l2(from_client, vlans) / ip / payload
        out.append((t, pkt))
        step = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        if from_client:
            c_seq += step
        else:
            s_seq += step

    send(True, "S")
    send(False, "SA")
    send(True, "A")
    if tls:
        req = _tls_payload(rng, rng.randint(300, 600))
    else:
        req = b"GET /item/%d HTTP/1.1\r\nHost: app.local\r\n\r\n" % rng.randint(1, 9999)
    send(True, "PA", req)
    send(False, "A")
    segments = rng.randint(3, 6)
    for i in range(segments):
        size = 1400
        if tls:
            data = _tls_payload(rng, size)
        else:
            data = (b"HTTP/1.1 200 OK\r\nContent-Length: 8000\r\n\r\n" if i == 0 else b"") 
            data += b"x" * (size - len(data))
        send(False, "PA" if i == segments - 1 else "A", data)
        if i % 2 == 1 or i == segments - 1:
            send(True, "A")
    send(True, "FA")
    send(False, "FA")
    send(True, "A")
    return out


def test_breach_session(rng, t, vlans, cip="10.10.10.66", sip="10.20.20.25"):
    """A web request whose server response carries the harmless IDS test pattern
    (output of `id` for root). Only the server-to-client direction contains it."""
    out, c_seq, s_seq = [], rng.randint(1, 2**31), rng.randint(1, 2**31)
    cport, sport = 45555, 80

    def send(from_client, flags, payload=b""):
        nonlocal t, c_seq, s_seq
        t += 0.001
        if from_client:
            ip = IP(src=cip, dst=sip) / TCP(sport=cport, dport=sport, flags=flags, seq=c_seq, ack=s_seq if "A" in flags else 0)
        else:
            ip = IP(src=sip, dst=cip) / TCP(sport=sport, dport=cport, flags=flags, seq=s_seq, ack=c_seq)
        out.append((t, _l2(from_client, vlans) / ip / payload))
        step = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        if from_client:
            c_seq += step
        else:
            s_seq += step

    send(True, "S"); send(False, "SA"); send(True, "A")
    send(True, "PA", b"GET /cgi-bin/status.cgi?cmd=id HTTP/1.1\r\nHost: app.local\r\n\r\n")
    body = b"uid=0(root) gid=0(root) groups=0(root)\n"
    send(False, "PA", b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    send(True, "A"); send(True, "FA"); send(False, "FA"); send(True, "A")
    return out


def dns_pair(rng, t, cip, vlans):
    q = rng.randint(1, 65535)
    name = f"host{rng.randint(1, 500)}.example.com"
    query = _l2(True, vlans) / IP(src=cip, dst="10.20.20.53") / UDP(sport=rng.randint(20000, 60000), dport=53) / DNS(id=q, rd=1, qd=DNSQR(qname=name))
    sp = query[UDP].sport
    reply = _l2(False, vlans) / IP(src="10.20.20.53", dst=cip) / UDP(sport=53, dport=sp) / DNS(id=q, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="10.20.20.%d" % rng.randint(10, 200)))
    return [(t, query), (t + rng.uniform(0.0005, 0.003), reply)]


def generate(out, sessions=200, dns=50, tls_share=0.2, vlans=True, duration=10.0, seed=1, breach=False):
    rng = random.Random(seed)
    timed = []
    for i in range(sessions):
        start = rng.uniform(0, duration)
        cip = f"10.10.10.{rng.randint(10, 250)}"
        sip = f"10.20.20.{rng.randint(10, 40)}"
        timed += tcp_session(rng, start, cip, sip, 20000 + i, rng.random() < tls_share, vlans)
    for _ in range(dns):
        timed += dns_pair(rng, rng.uniform(0, duration), f"10.10.10.{rng.randint(10, 250)}", vlans)
    if breach:
        timed += test_breach_session(rng, duration / 2, vlans)
    timed.sort(key=lambda x: x[0])
    pkts = []
    for ts, p in timed:
        p.time = 1_793_000_000 + ts
        pkts.append(p)
    wrpcap(out, pkts)
    return len(pkts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="bench/cases/clean.pcap")
    ap.add_argument("--tls-share", type=float, default=0.2)
    ap.add_argument("--no-vlans", action="store_true")
    a = ap.parse_args()
    n = generate(a.out, tls_share=a.tls_share, vlans=not a.no_vlans)
    print(f"Wrote {n} packets to {a.out}")
