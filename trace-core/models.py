"""Deprecated shim.

The original hand-written models lived here. The working schema now lives in
``trace_api.models``. This module re-exports it so nothing that still says
``import models`` breaks.
"""

from trace_api.models import Finding, Scan, TriageEvent  # noqa: F401

__all__ = ["Scan", "Finding", "TriageEvent"]
