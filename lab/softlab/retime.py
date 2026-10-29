"""Re-time a soft-lab recording from the broker's timestamp trailers, as a capture that uses a
packet broker's hardware timestamps does.

The soft lab's broker adds to every frame it sends a 20-byte trailer holding the frame's
scheduled departure time on its line-rate schedule (ports.py). This rewrites the pcap: each
frame's timestamp becomes that departure time, in nanoseconds, and the trailer is removed, so
the frames are exactly what the broker sent. Frames without a trailer did not come from the
broker (for example the tool host's own IPv6 housekeeping) and are left out.

    python -m lab.softlab.retime capture.pcap          # rewrites the file in place
"""
import os
import struct
import sys

from lab.softlab.ports import unstamp

NS_MAGIC = 0xA1B23C4D


def retime(path):
    """Rewrite path in place. Returns (frames kept, frames left out)."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return 0, 0
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, NS_MAGIC):
        end = "<"
    elif struct.unpack(">I", data[:4])[0] in (0xA1B2C3D4, NS_MAGIC):
        end = ">"
    else:
        raise ValueError(f"{path}: not a pcap file (record it with dumpcap -P)")
    _, major, minor, zone, sigfigs, snaplen, linktype = struct.unpack(end + "IHHiIII", data[:24])
    out = [struct.pack("<IHHiIII", NS_MAGIC, 2, 4, 0, 0, max(snaplen, 65535), linktype)]
    kept = dropped = 0
    pos = 24
    while pos + 16 <= len(data):
        _, _, incl, orig = struct.unpack(end + "IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        frame, t, _ = unstamp(frame)
        if t is None:
            dropped += 1
            continue
        ns = int(round(t * 1e9))
        out.append(struct.pack("<IIII", ns // 1_000_000_000, ns % 1_000_000_000, len(frame), len(frame)) + frame)
        kept += 1
    tmp = path + ".retime"
    with open(tmp, "wb") as f:
        f.write(b"".join(out))
    os.replace(tmp, path)
    return kept, dropped


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(p, "kept %d, left out %d" % retime(p))
