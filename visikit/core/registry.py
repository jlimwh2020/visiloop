"""Plug-in registry: every detector and fix registers itself here."""
import importlib
import pkgutil

DETECTORS: dict[str, type] = {}
FIXES: dict[str, type] = {}


def detector(cls):
    """Class decorator: @detector registers a detector by its `fault` name."""
    DETECTORS[cls.fault] = cls
    return cls


def fix(cls):
    """Class decorator: @fix registers a fix by the `fault` it repairs."""
    FIXES[cls.fault] = cls
    return cls


def applicable(cls, ctx) -> bool:
    """A check runs on a capture (the default) or on interface counters; skip it when that data is missing."""
    source = getattr(cls, "source", "pcap")
    return bool(ctx.counters) if source == "counters" else bool(ctx.pcap)


def load_plugins():
    """Import every module in visikit.detectors and visikit.fixes."""
    for pkg_name in ("visikit.detectors", "visikit.fixes"):
        pkg = importlib.import_module(pkg_name)
        for mod in pkgutil.iter_modules(pkg.__path__):
            importlib.import_module(f"{pkg_name}.{mod.name}")
    return DETECTORS, FIXES
