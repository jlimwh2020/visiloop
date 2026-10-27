"""Common data format shared by every VisiKit plug-in."""
from dataclasses import dataclass, field, asdict


@dataclass
class ToolProfile:
    """What a monitoring tool needs from its feed."""
    tool_type: str                  # "NDR", "IDS", "APM", "SIEM"
    needs_both_directions: bool
    needs_full_payload: bool
    max_rate_gbps: float            # speed of the tool's input port
    required_vlans: list[int] = field(default_factory=list)
    max_encrypted_share: float = 1.0  # above this, the tool loses most visibility


@dataclass
class FeedContext:
    """One tool feed being checked."""
    feed: str                       # e.g. "ids-1"
    pcap: str                       # path to a capture taken from the tool's input
    profile: ToolProfile
    ingress: str | None = None      # lossless capture of what the broker receives from its TAPs (optional)


@dataclass
class Finding:
    fault: str                      # "duplicates", "one_way", "packet_drops", ...
    feed: str
    severity: str                   # "low" | "medium" | "high"
    metric: float                   # measured value, e.g. 0.07 = 7%
    threshold: float                # threshold it was compared against
    evidence: list[int] = field(default_factory=list)   # frame numbers proving it
    detail: str = ""                # short machine-written description
    explanation: str = ""           # filled in later by the Muse Spark agent

    def to_dict(self):
        return asdict(self)


@dataclass
class Fix:
    fault: str                      # which fault this repairs
    action: str                     # "dedup", "aggregate", "load_balance", "filter", "slice", "vlan"
    params: dict = field(default_factory=dict)
    broker_config: dict = field(default_factory=dict)   # vendor-neutral rule

    def to_dict(self):
        return asdict(self)
