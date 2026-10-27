"""Encrypted traffic: recommend a decryption point before the tool.

This cannot be verified offline (it needs the customer's keys or a decryption
appliance), so simulate() returns None and the result is reported as advice.
"""
from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class DecryptAdvice:
    fault = "encrypted_share"
    action = "decrypt_advice"
    stage = 90

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"encrypted_share": finding.metric, "tool_limit": ctx.profile.max_encrypted_share,
                           "placement": f"TLS decryption point between the broker and {ctx.feed}",
                           "exempt": "privacy-sensitive categories (banking, healthcare) per policy",
                           "alternative": "send encrypted flows to NDR for metadata/JA4 analysis instead"},
                   broker_config={"tool_port": ctx.feed, "service_chain": ["tls_decryption", ctx.feed]})

    def simulate(self, pcaps, ctx, fix, workdir):
        return None
