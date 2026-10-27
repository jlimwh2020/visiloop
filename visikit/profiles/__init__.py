import os
import yaml
from visikit.core.schema import ToolProfile

_PATH = os.path.join(os.path.dirname(__file__), "tools.yaml")


def load_profile(tool_type: str, required_vlans=None) -> ToolProfile:
    with open(_PATH) as f:
        data = yaml.safe_load(f)[tool_type]
    return ToolProfile(tool_type=tool_type, required_vlans=required_vlans or [], **data)
