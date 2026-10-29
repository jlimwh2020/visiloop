"""Lab traffic for the soft lab: servers on the lab server, traffic mixes from the lab client.

    python -m lab.softlab.traffic serve --state DIR             # in vl-server: HTTP :80, HTTPS :443, DNS :53
    python -m lab.softlab.traffic mix --seconds 20              # in vl-client: web mix (HTTP, HTTPS, DNS)
    python -m lab.softlab.traffic mix --seconds 20 --https-only
"""
import argparse
import http.server
import os
import random
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import urllib.request

SERVER = "10.10.0.2"
BLOB = os.urandom(1 << 20)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        n = int(self.path.rsplit("/", 1)[-1]) if self.path.startswith("/bytes/") else 2000
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.end_headers()
        sent = 0
        while sent < n:
            chunk = BLOB[:min(len(BLOB), n - sent)]
            self.wfile.write(chunk)
            sent += len(chunk)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    while True:
        q, addr = s.recvfrom(512)
        # answer: same id and question, one A record 10.10.0.2
        ans = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:] + \
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(SERVER)
        s.sendto(ans, addr)


def serve(state):
    cert, key = os.path.join(state, "lab.crt"), os.path.join(state, "lab.key")
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj",
                        "/CN=lab-server.visiloop.test", "-keyout", key, "-out", cert], check=True, capture_output=True)
    http_srv = Server(("0.0.0.0", 80), Handler)
    https_srv = Server(("0.0.0.0", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)
    for target in (http_srv.serve_forever, https_srv.serve_forever, dns_server):
        threading.Thread(target=target, daemon=True).start()
    print("lab server: HTTP :80, HTTPS :443, DNS :53", flush=True)
    while True:
        time.sleep(3600)


def dns_query(name):
    q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(q, (SERVER, 53))
        s.recvfrom(512)
    except OSError:
        pass
    finally:
        s.close()


# Lab traffic goes straight to the lab server: ignore any proxy set in the environment (HTTPS_PROXY etc.)
NO_PROXY = urllib.request.ProxyHandler({})


def fetch(url, ctx=None):
    handlers = [NO_PROXY] + ([urllib.request.HTTPSHandler(context=ctx)] if ctx else [])
    try:
        with urllib.request.build_opener(*handlers).open(url, timeout=10) as r:
            while r.read(65536):
                pass
    except OSError:
        pass


def mix(seconds, https_only=False):
    """Web browsing and downloads: plain HTTP about two thirds of the bytes (unless HTTPS only), plus DNS."""
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    end = time.time() + seconds
    while time.time() < end:
        for name in ("www.lab.test", "files.lab.test"):
            dns_query(name)
        if not https_only:
            fetch(f"http://{SERVER}/bytes/{random.choice([600000, 900000, 1200000])}")
            fetch(f"http://{SERVER}/page/1")
        fetch(f"https://{SERVER}/bytes/{random.choice([300000, 500000])}", ctx)
        time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--state", required=True)
    m = sub.add_parser("mix")
    m.add_argument("--seconds", type=float, default=20)
    m.add_argument("--https-only", action="store_true")
    a = ap.parse_args()
    if a.cmd == "serve":
        serve(a.state)
    else:
        mix(a.seconds, a.https_only)


if __name__ == "__main__":
    main()
