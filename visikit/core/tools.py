"""Find and run Wireshark command-line tools on Windows, WSL or Linux."""
import os
import shutil
import subprocess

_WIN_DIRS = [r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"]


def find_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    if os.name == "nt":
        for d in _WIN_DIRS:
            candidate = os.path.join(d, name + ".exe")
            if os.path.exists(candidate):
                return candidate
    raise FileNotFoundError(f"{name} not found. Install Wireshark (with TShark) and try again.")


def run(name: str, args: list[str]) -> str:
    """Run a tool and return its standard output as text."""
    result = subprocess.run([find_tool(name), *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{name} failed: {result.stderr.strip()}")
    return result.stdout


def packet_count(pcap: str) -> int:
    out = run("capinfos", ["-c", "-M", "-T", pcap])
    # Tab-separated: file name, packet count
    last = out.strip().splitlines()[-1]
    return int(last.split("\t")[-1])


def fields(pcap: str, names: list[str], display_filter: str | None = None) -> list[list[str]]:
    """Extract fields per packet with tshark. Returns one list of strings per packet."""
    args = ["-r", pcap, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    if display_filter:
        args += ["-Y", display_filter]
    for n in names:
        args += ["-e", n]
    out = run("tshark", args)
    return [line.split("\t") for line in out.splitlines() if line.strip()]
