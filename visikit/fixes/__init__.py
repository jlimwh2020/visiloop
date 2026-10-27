"""Fixes. Each module defines one class decorated with @fix.

Every fix has:
  fault    - the fault it repairs
  action   - the broker change, in vendor-neutral terms
  stage    - order in the simulated broker pipeline (lower runs first)
  config(ctx, finding) -> Fix         settings calculated from the measurements
  simulate(pcaps, ctx, fix, workdir)  -> list of tool-port captures after the change,
                                        or None when the fix cannot be verified offline
"""
