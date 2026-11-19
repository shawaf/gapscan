"""Map findings to the controls of the target packs (ARCHITECTURE.md section 1, the gap model).

Generic: it knows no standard. The packs say which controls a finding's evidence maps to (from
their own tables, never from model output); this sets them on the finding.
"""

from __future__ import annotations

from collections.abc import Sequence

from .core.interfaces import TargetPack
from .core.models import Finding, MappingSource


def map_controls(findings: Sequence[Finding], packs: Sequence[TargetPack]) -> None:
    """Set `controls` in place, pack by pack in the given order. A finding no pack maps keeps
    what it had; one that maps gets mapping_source 'table'."""
    for f in findings:
        refs = [r for pack in packs for r in pack.controls_for(f)]
        if refs:
            f.controls = refs
            f.mapping_source = MappingSource.TABLE
