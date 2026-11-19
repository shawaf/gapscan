"""Coverage per target: for every registered
standard, each control in scope with an honest status. Computed in Python, never by the model.

- evidence_of_failure: an open finding maps to the control.
- no_issue_found_by_tools: no open finding, and the pack says automated evidence can speak to the
  control (`TargetPack.checkable`). This is NOT proof the control is met.
- manual_review_required: nothing automated can speak to it; it is never counted as passed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from ..core.interfaces import TargetPack
from .schema import AsvsStatus, ControlCoverage, TargetCoverage


def target_coverage(
    pack: TargetPack, failing: Mapping[str, Sequence[str]], level: int | None = None
) -> TargetCoverage:
    """`failing` maps a control id of this pack to the open findings that map to it. With
    `level`, controls of a higher level are out of scope (standards without levels ignore it)."""
    checkable = pack.checkable()
    controls: list[ControlCoverage] = []
    for c in pack.controls():
        if level is not None and c.level is not None and c.level > level:
            continue
        cid = c.ref.control_id
        ids = list(failing.get(cid, []))
        status: AsvsStatus
        if ids:
            status = "evidence_of_failure"
        elif cid in checkable:
            status = "no_issue_found_by_tools"
        else:
            status = "manual_review_required"
        controls.append(ControlCoverage(id=cid, title=c.title, group=c.group, level=c.level,
                                        status=status, finding_ids=ids))  # fmt: skip
    count = {s: sum(1 for c in controls if c.status == s) for s in
             ("evidence_of_failure", "no_issue_found_by_tools", "manual_review_required")}  # fmt: skip
    total = len(controls)
    tool_side = count["evidence_of_failure"] + count["no_issue_found_by_tools"]
    has_levels = any(c.level is not None for c in controls)
    return TargetCoverage(
        target=pack.id, name=pack.name, version=pack.version,
        level=level if has_levels else None, total=total, **count,
        tool_verifiable_pct=round(100 * tool_side / total, 1) if total else 0.0, controls=controls,
    )  # fmt: skip


def coverage_by_target(
    packs: Iterable[TargetPack],
    open_controls: Iterable[tuple[str, Iterable[tuple[str, str]]]],
    level: int | None = None,
) -> list[TargetCoverage]:
    """`open_controls` is (finding id, its (target, control id) pairs) for each open finding."""
    failing: dict[str, dict[str, list[str]]] = {}
    for fid, refs in open_controls:
        for target, cid in refs:
            ids = failing.setdefault(target, {}).setdefault(cid, [])
            if fid not in ids:
                ids.append(fid)
    return [target_coverage(p, failing.get(p.id, {}), level) for p in packs]
