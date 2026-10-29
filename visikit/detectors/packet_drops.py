"""Packet drops: the capture is missing packets the endpoints clearly exchanged.

Signal: ACKs for data never seen in the capture, and sequence gaps that are never
filled. On a monitoring feed these mean the SPAN port, broker or tool dropped packets.

VisiLoop runs its own sequence analysis (gap_analysis) rather than tshark's flags, so
that three things that look like loss are not reported as a visibility fault:
  - sliced frames: each segment is measured by the length its IP header states;
  - network loss before the monitoring point: a gap that a retransmission fills later
    is what was really on the wire (found in the soft lab, where the shaped access link
    drops some bursts);
  - reordering between the two directions when a broker merges TAP legs: an ACK seen
    up to 10 ms before its data.
"""
from collections import defaultdict, deque

from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.01      # more than 1% of TCP packets flagged is a fault
ETH_HEADER = 14


def has_sliced_frames(pcap):
    rows = fields(pcap, ["frame.len", "ip.len", "ipv6.plen"], "ip or ipv6")
    for r in rows:
        r += [""] * (3 - len(r))
        stated = int(r[1]) if r[1] else (int(r[2]) + 40 if r[2] else 0)
        if stated > int(r[0]) - ETH_HEADER:
            return True
    return False


REORDER = 0.010      # seconds: data seen this soon after an ACK for it was reordered, not lost


def judge(p, next_seq, gaps, flagged):
    """An ACK that ran ahead of the capture, REORDER seconds on: is the data it acknowledged still missing?"""
    _, k, a, f, g = p
    if g is None:
        if next_seq[k] < a:
            flagged.append(f)
    elif g in gaps[k]:                                 # the gap is still open: the capture missed that data
        flagged.append(f)
        g[4] = "confirmed"


def gap_analysis(pcap):
    """Frames showing data missing from the capture. Returns (flagged frames, TCP packets, gaps filled later).

    Segments are measured by the length their IP header states, so sliced frames are not taken for gaps.
    Two signals, each with the case it must not be confused with:
      - a sequence gap: data before this segment never arrived. If a retransmission fills the gap later,
        the data was lost on the network before the monitoring point (the TAP saw what was on the wire),
        so it is not a visibility fault and is not counted.
      - an ACK for data the capture never saw (beyond everything seen, or inside an open gap): the endpoint
        received it, the capture did not. If the data appears within REORDER seconds, the two directions were
        merged slightly out of order (normal when a broker aggregates two TAP legs), and it is not counted.
        A gap the receiver acknowledged stays counted even if a retransmission appears later.
    """
    names = ["frame.number", "tcp.stream", "ip.src", "tcp.seq", "tcp.ack", "tcp.flags.syn", "tcp.flags.fin",
             "tcp.flags.ack", "ip.len", "ip.hdr_len", "tcp.hdr_len", "ipv6.src", "ipv6.plen", "tcp.srcport",
             "frame.time_relative"]
    rows = fields(pcap, names, "tcp", occurrence="l")
    next_seq = {}                      # (stream, sender) -> highest sequence end seen
    peer = {}                          # (stream, sender) -> the other side's key
    gaps = defaultdict(list)           # (stream, sender) -> open gaps [start, end, frame, covered bytes, acked]
    pending = deque()                  # ACKs to judge after REORDER: (time, data sender, ack, frame, gap or None)
    flagged, filled = [], 0
    for r in rows:
        r += [""] * (len(names) - len(r))
        frame, stream, src, seq, ack, syn, fin, has_ack, iplen, iphl, tcphl, src6, plen6, sport, t = r
        if not iplen and plen6:                       # IPv6: payload length covers TCP header + data
            iplen, iphl = plen6, "0"
        if not seq or not iplen:
            continue
        t = float(t or 0)
        key = (stream, f"{src or src6}:{sport}")
        seq, payload = int(seq), int(iplen) - int(iphl) - int(tcphl)
        end = seq + payload + (syn in ("1", "True")) + (fin in ("1", "True"))
        if key in next_seq and seq > next_seq[key]:
            gaps[key].append([next_seq[key], seq, int(frame), 0, False])
        elif key in next_seq and seq < next_seq[key] and payload and gaps[key]:
            for g in gaps[key]:                       # a retransmission (or a late segment): does it fill a gap?
                g[3] += max(0, min(end, g[1]) - max(seq, g[0]))
            done = [g for g in gaps[key] if g[3] >= g[1] - g[0]]
            for g in done:
                if g[4] == "confirmed":
                    flagged.append(g[2])              # the receiver had already acknowledged it: still missing here
                else:
                    filled += 1
            gaps[key] = [g for g in gaps[key] if g[3] < g[1] - g[0]]
        next_seq[key] = max(next_seq.get(key, 0), end)
        if has_ack in ("1", "True") and ack:
            other = peer.get(key)
            if other is None:
                other = next((k for k in next_seq if k[0] == stream and k != key), None)
                if other:
                    peer[key], peer[other] = other, key
            if other:
                a = int(ack)
                if a > next_seq[other]:               # acknowledges data beyond anything seen
                    pending.append((t, other, a, int(frame), None))
                for g in gaps[other]:                 # acknowledges data inside a gap: the receiver got it
                    if not g[4] and g[0] < a:
                        g[4] = True
                        pending.append((t, other, a, int(frame), g))
        # ACKs older than the reordering window: missing data unless it has appeared since
        while pending and t - pending[0][0] > REORDER:
            judge(pending.popleft(), next_seq, gaps, flagged)
    for p in pending:
        judge(p, next_seq, gaps, flagged)
    for k, gs in gaps.items():
        flagged += [g[2] for g in gs]
    return sorted(set(flagged)), len(rows), filled


@detector
class PacketDrops:
    fault = "packet_drops"

    def run(self, ctx: FeedContext) -> list[Finding]:
        flagged, tcp_total, filled = gap_analysis(ctx.pcap)
        method = ""
        if has_sliced_frames(ctx.pcap):
            method = (". Some frames on this feed are sliced, so segments were measured by the length in their IP "
                      "headers: slicing is ruled out as the cause, and these packets are genuinely missing")
        if filled:
            method += (f". Not counted: {filled} gaps that retransmissions filled later (packets lost on the network "
                       "before the monitoring point, which the feed rightly shows)")
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
