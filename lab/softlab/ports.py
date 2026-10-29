"""Ports for the soft lab's switch and broker daemons: raw sockets, pacing, buffers and counters.

Each port is a real Linux network interface (one end of a veth pair). Input ports read every
frame with an AF_PACKET socket; output ports send frames at a fixed line rate with a buffer, so
a port offered more than its speed fills its buffer and then discards, as a real port does.

Timing-faithful: a Python daemon gets the CPU in slices, so the moment it sends a frame says
little about when a real port would have. Every frame is scheduled from its kernel arrival time
on the lab link: it leaves a fixed LATENCY later, then is paced at the port's line rate, and the
buffer is a virtual queue on that schedule, so a port discards exactly when its real counterpart
would. The scheduled departure time travels with the frame in a 20-byte trailer, as packet
brokers' hardware timestamps do: the broker takes a frame's arrival time from the switch's
trailer, and the recording is re-timed from the broker's trailer (retime.py), so pauses of the
daemons never show in the timing VisiLoop measures. The trailer also carries the time the
original frame was on the lab link, at which every port counts it (Port.count).
Counters are written to a JSON file that an SNMP agent serves as standard IF-MIB counters.
"""
import collections
import heapq
import json
import os
import select
import socket
import struct
import threading
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SOL_PACKET, PACKET_STATISTICS = 263, 6
SO_TIMESTAMPNS = 35
LATENCY = 0.02               # seconds from arrival to departure (before pacing): hides the daemon's pauses
LATE = 0.005                 # a frame sent this much after its scheduled time is counted late
HORIZON = 3.0                # counters are served as of this long ago on the lab's wire clock (Port.count): a busy
                             # machine can leave a daemon seconds behind
MAGIC = b"VLts"              # trailer: MAGIC + scheduled departure + wire time, in ns (big-endian u64 each)
TRAILER = 20


def stamp(frame, depart, wire):
    return frame + MAGIC + struct.pack("!QQ", int(depart * 1e9), int(wire * 1e9))


def unstamp(data):
    """(frame, departure, wire time) for a frame with a trailer, else (data, None, None).
    Departure: when the last port scheduled it (re-timing). Wire time: when the original frame was on the lab
    link (counting: every port on the path counts a frame at that one time, so counters agree but for loss)."""
    if len(data) >= 14 + TRAILER and data[-TRAILER:-16] == MAGIC:
        depart, wire = struct.unpack("!QQ", data[-16:])
        return data[:-TRAILER], depart / 1e9, wire / 1e9
    return data, None, None


class Port:
    def __init__(self, iface, name, index, speed_mbps, rate_mbps=None, buffer_bytes=256 * 1024, rx=False, stamp=False):
        self.iface, self.name, self.index, self.speed_mbps = iface, name, index, speed_mbps
        self.stamp = stamp           # add the departure-time trailer to every frame sent
        self.rate_mbps, self.buffer_bytes = rate_mbps, buffer_bytes
        self.c = dict(in_pkts=0, out_pkts=0, in_octets=0, out_octets=0, in_discards=0, out_discards=0, in_errors=0)
        # Counters on the lab's wire clock: every port counts a frame at the time the original was on the lab
        # link (carried in the trailer), served as of HORIZON ago. Frames queued in a port or in flight between
        # the daemons are then never counted by one port and not yet by the next: any difference is real loss.
        self.events, self.seq = [], 0                    # a heap of (wire time, n, key, count)
        self.shown = dict(self.c)
        self.lock = threading.Lock()                     # the SNMP agent reads from its own thread
        self.queue, self.next_free, self.last_departure, self.late = collections.deque(), 0.0, 0.0, 0
        if rx:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 << 20)
            self.sock.bind((iface, ETH_P_ALL))
            self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)    # kernel arrival time of each frame
        else:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)     # send only: receives nothing
            self.sock.bind((iface, 0))
        self.sock.setblocking(False)
        self.socket_drops = 0

    # input side
    def recv_all(self, limit=100000):
        """Every frame waiting on an input port: list of (arrival time, frame, outgoing, wire time). All of them, so that
        merging several inputs by time never processes one input's newer frames before another's older ones."""
        out = []
        for _ in range(limit):
            try:
                data, anc, _, addr = self.sock.recvmsg(65535, 64)
            except (BlockingIOError, InterruptedError):
                break
            ts = 0.0
            for level, kind, raw in anc:
                if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
                    sec, nsec = struct.unpack("qq", raw[:16])
                    ts = sec + nsec / 1e9
            data, depart, wire = unstamp(data)
            out.append((depart or ts, data, addr[2] == PACKET_OUTGOING, wire or depart or ts))
        return out

    def count(self, key, n, t):
        """Count n for key, for a frame scheduled at time t on this hop."""
        self.c[key] += n
        with self.lock:
            heapq.heappush(self.events, (t, self.seq, key, n))
            self.seq += 1

    def counters(self, now=None):
        """The counters as of HORIZON ago on the wire clock (what the SNMP agent serves)."""
        cutoff = (now or time.time()) - HORIZON
        with self.lock:
            ev = self.events
            while ev and ev[0][0] <= cutoff:
                _, _, key, n = heapq.heappop(ev)
                self.shown[key] += n
            return dict(self.shown)

    def kernel_drops(self):
        """Frames the kernel dropped before this daemon read them (the daemon fell behind)."""
        try:
            raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            self.socket_drops += int.from_bytes(raw[4:8], "little")
        except OSError:
            pass
        return self.socket_drops

    # output side
    def enqueue(self, frame, ts=None, wire=None):
        """Schedule a frame that arrived at time ts: it leaves at ts + LATENCY, paced at line rate. wire: when the
        original frame was on the lab link (counted then; defaults to ts)."""
        eligible = (ts or time.time()) + LATENCY
        wire = wire or ts or eligible
        if self.rate_mbps is None:                       # no rate limit (a passive TAP leg): same timing, in order
            depart = max(eligible, self.last_departure)
        else:
            backlog = max(0.0, self.next_free - eligible) * self.rate_mbps * 1e6 / 8     # bytes queued ahead
            if backlog + len(frame) > self.buffer_bytes:
                self.count("out_discards", 1, wire)      # buffer full: the port discards, as a real port does
                return
            depart = max(eligible, self.next_free)
            self.next_free = depart + len(frame) * 8 / (self.rate_mbps * 1e6)
        self.last_departure = depart
        self.count("out_pkts", 1, wire)
        self.count("out_octets", len(frame), wire)
        self.queue.append((depart, frame, wire))

    def ready(self, now):
        # Sent as soon as its scheduled departure has come, catching up after a pause: the timing that counts
        # is the departure in the trailer, not when the daemon got round to sending
        return bool(self.queue) and self.queue[0][0] <= now

    def send_next(self, now):
        """Send the frame at the head of the queue (its departure time has come)."""
        depart, frame, wire = self.queue.popleft()
        if now - depart > LATE:
            self.late += 1
        try:
            self.sock.send(stamp(frame, depart, wire) if self.stamp else frame)
        except OSError:
            pass                                         # a veth send does not fail while the lab is up

    def due(self):
        return self.queue[0][0] if self.queue else None


def flush(outputs, now):
    """Send every frame due by now, across all output ports in departure order. (Port by port would
    send, say, all of TAP leg A's frames before leg B's, and ACKs could overtake the data they ack.)"""
    while True:
        ready = [o for o in outputs if o.ready(now)]
        if not ready:
            return
        min(ready, key=lambda o: o.queue[0][0]).send_next(now)


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


class Config:
    """A JSON file the orchestrator rewrites to change the setup; re-read when it changes."""
    def __init__(self, path):
        self.path, self.mtime, self.data = path, None, {}

    def changed(self):
        try:
            m = os.stat(self.path).st_mtime_ns
        except FileNotFoundError:
            return False
        if m == self.mtime:
            return False
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except (ValueError, OSError):
            return False                                 # half-written: try again next time
        self.mtime = m
        return True


STALLS = collections.Counter()   # how late the loop woke for a due frame, in ms buckets (diagnostics)


def loop(inputs, outputs, on_frame, every_second, hold=0.0):
    """The event loop: read inputs, pace outputs, run housekeeping twice a second.

    hold: for a daemon whose inputs carry timestamp trailers (the broker), frames are held this long and
    then handled in timestamp order, so a frame the switch daemon sent late is still merged in its place."""
    import gc
    import heapq
    gc.freeze()                                          # fewer collector pauses while forwarding
    socks = {p.sock: p for p in inputs}
    last = 0.0
    held, seq = [], 0
    while True:
        now = time.time()                                # kernel arrival stamps are wall-clock time too
        dues = [d for d in (o.due() for o in outputs) if d is not None]
        if held:
            dues.append(held[0][0] + hold)
        timeout = max(0.0, min(dues) - now) if dues else 0.1
        ready, _, _ = select.select(list(socks), [], [], min(timeout, 0.1))
        if dues:
            over = time.time() - min(dues)
            if over > 0.001:
                STALLS[min(int(over * 1000), 50)] += 1
        # Merge the inputs in the order frames arrived, as a broker's merge does
        batch = [(ts, i, socks[s], frame, outgoing, wire) for i, s in enumerate(ready)
                 for ts, frame, outgoing, wire in socks[s].recv_all()]
        if hold:
            for ts, i, port, frame, outgoing, wire in batch:
                heapq.heappush(held, (ts, seq, port, frame, outgoing, wire))
                seq += 1
            cutoff = time.time() - hold
            batch = []
            while held and held[0][0] <= cutoff:
                batch.append(heapq.heappop(held))
        else:
            batch.sort(key=lambda x: (x[0], x[1]))
        for n, (ts, _, port, frame, outgoing, wire) in enumerate(batch, 1):
            on_frame(port, frame, outgoing, ts, wire)
            if n % 32 == 0:                              # a long batch: keep sending on time meanwhile
                flush(outputs, time.time())
        now = time.time()
        flush(outputs, now)
        if now - last >= 0.5:
            last = now
            every_second()
