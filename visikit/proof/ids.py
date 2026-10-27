"""Detection proof: run Suricata on the feed before and after VisiLoop's fix.

Uses the harmless test signature in visiloop.rules. On Linux Suricata is called
directly; on Windows it runs inside WSL (Ubuntu), with paths converted.
"""
import json
import os
import shutil
import subprocess
import tempfile

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "visiloop.rules")
# Traffic routed between VLANs carries a different tag in each direction; don't split flows by VLAN
SURICATA_OPTS = ["-k", "none", "--set", "vlan.use-for-tracking=false"]


def _to_wsl(path: str) -> str:
    p = os.path.abspath(path)
    drive, rest = os.path.splitdrive(p)
    return f"/mnt/{drive[0].lower()}{rest.replace(os.sep, '/')}"


def _command(pcap, outdir):
    if shutil.which("suricata"):
        return ["suricata", "-r", pcap, "-S", RULES, "-l", outdir, *SURICATA_OPTS]
    if os.name == "nt" and shutil.which("wsl"):
        return ["wsl", "suricata", "-r", _to_wsl(pcap), "-S", _to_wsl(RULES), "-l", _to_wsl(outdir), *SURICATA_OPTS]
    return None


def available() -> bool:
    if shutil.which("suricata"):
        return True
    if os.name == "nt" and shutil.which("wsl"):
        r = subprocess.run(["wsl", "which", "suricata"], capture_output=True, text=True)
        return r.returncode == 0 and bool(r.stdout.strip())
    return False


def run_suricata(pcap: str) -> list[dict]:
    """Return the alerts Suricata raises on a capture."""
    outdir = tempfile.mkdtemp(prefix="visiloop_ids_")
    cmd = _command(pcap, outdir)
    if not cmd:
        raise RuntimeError("Suricata not found (install it, or on Windows install it inside WSL Ubuntu)")
    r = subprocess.run(cmd, capture_output=True, text=True)
    eve = os.path.join(outdir, "eve.json")
    if not os.path.exists(eve):
        raise RuntimeError(f"Suricata did not run: {(r.stderr or r.stdout).strip()[-300:]}")
    alerts = []
    with open(eve, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e.get("event_type") == "alert":
                a = e["alert"]
                alerts.append({"signature": a.get("signature"), "sid": a.get("signature_id"),
                               "src": f"{e.get('src_ip')}:{e.get('src_port')}",
                               "dst": f"{e.get('dest_ip')}:{e.get('dest_port')}"})
    shutil.rmtree(outdir, ignore_errors=True)
    return alerts


def prove_detection(before_pcap: str, after_pcaps: list[str]) -> dict:
    before = run_suricata(before_pcap)
    after = [a for p in after_pcaps for a in run_suricata(p)]
    return {"before": len(before), "after": len(after), "before_alerts": before, "after_alerts": after}
