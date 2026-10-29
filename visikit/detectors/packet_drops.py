"""Packet drops: the capture is missing packets the endpoints clearly exchanged.

Signal: tshark flags ACKs for data never seen in the capture (ack_lost_segment)
and sequence gaps (lost_segment). On a monitoring feed these usually mean the
SPAN port, broker or tool dropped packets, not the network itself.

Sliced feeds: tshark measures each segment by the bytes captured, so every sliced
segment would look like missing data. When a feed contains sliced frames, VisiLoop
runs its own sequence-gap analysis, measuring each segment by the length its IP
header states, so slicing is not mistaken for loss.
"""
from collections import defaultdict

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.01      # more than 1% of TCP packets flagged is a fault
FILTER = "tcp.analysis.ack_lost_segment or tcp.analysis.lost_segment"
ETH_HEADER = 14


def has_sliced_frames(pcap):
    rows = fields(pcap, ["frame.len", "ip.len"], "ip")
    return any(len(r) > 1 and r[1] and int(r[1]) > int(r[0]) - ETH_HEADER for r in rows)


def gap_analysis(pcap):
    """Frames showing missing data, judged by IP-stated segment lengths. Returns (flagged, tcp_total)."""
    names = ["frame.number", "tcp.stream", "ip.src", "tcp.seq", "tcp.ack", "tcp.flags.syn", "tcp.flags.fin",
             "tcp.flags.ack", "ip.len", "ip.hdr_len", "tcp.hdr_len"]
    rows = fields(pcap, names, "tcp", occurrence="l")
    next_seq = {}                      # (stream, sender) -> highest sequence end seen
    flagged = []
    sides = defaultdict(set)
    for r in rows:
        r += [""] * (len(names) - len(r))
        frame, stream, src, seq, ack, syn, fin, has_ack, iplen, iphl, tcphl = r
        if not seq or not iplen:
            continue
        seq, payload = int(seq), int(iplen) - int(iphl) - int(tcphl)
        end = seq + payload + (syn in ("1", "True")) + (fin in ("1", "True"))
        key = (stream, src)
        sides[stream].add(src)
        flag = False
        if key in next_seq and seq > next_seq[key]:
            flag = True                # data before this segment never arrived
        next_seq[key] = max(next_seq.get(key, 0), end)
        if has_ack in ("1", "True") and ack:
            other = [k for k in next_seq if k[0] == stream and k[1] != src]
            if other and int(ack) > next_seq[other[0]]:
                flag = True            # acknowledges data the capture never saw
        if flag:
            flagged.append(int(frame))
    return flagged, len(rows)


@detector
class PacketDrops:
    fault = "packet_drops"

    def run(self, ctx: FeedContext) -> list[Finding]:
        if has_sliced_frames(ctx.pcap):
            flagged, tcp_total = gap_analysis(ctx.pcap)
            method = (". Some frames on this feed are sliced, so segments were measured by the length in their IP "
                      "headers: slicing is ruled out as the cause, and these packets are genuinely missing")
        else:
            tcp_total = len(fields(ctx.pcap, ["frame.number"], "tcp"))
            flagged = [int(r[0]) for r in fields(ctx.pcap, ["frame.number"], FILTER)]
            method = ""
        if tcp_total == 0:
            return []
        share = len(flagged) / tcp_total
        if share <= THRESHOLD:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.03 else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=flagged[:20],
            detail=f"{len(flagged)} of {tcp_total} TCP packets show evidence of missing data ({share:.1%}){method}",
        )]
