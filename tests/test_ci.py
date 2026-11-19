"""The ready-to-copy CI templates in integrations/ci/."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_ci_templates_never_paste_pipeline_values_into_scripts() -> None:
    """`${{ }}` (GitHub) and `$(macro)` (Azure) are substituted into the script text before the
    shell runs, so a crafted branch name would become code. Values must come in through `env:`."""
    import re

    yaml = pytest.importorskip("yaml")
    root = Path(__file__).resolve().parent.parent / "integrations" / "ci"
    gh = yaml.safe_load((root / "github-actions.yml").read_text())
    for job in gh["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in step.get("run", ""), step.get("name")
            if "uses" in step:
                assert re.search(r"@[0-9a-f]{40}\b", step["uses"]), f"pin {step['uses']} to a SHA"
    az = yaml.safe_load((root / "azure-pipelines.yml").read_text())
    for step in az["steps"]:
        assert not re.search(r"\$\(", step.get("script", "")), step.get("displayName")


def test_the_composite_action_is_pinned_and_never_interpolates_into_scripts() -> None:
    """The reusable GitHub Action (`action.yml`): every `uses` is pinned to a commit SHA, and no
    `run:` script interpolates `${{ }}` (event values must arrive through `env:`)."""
    import re

    yaml = pytest.importorskip("yaml")
    repo = Path(__file__).resolve().parent.parent
    action = yaml.safe_load((repo / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    for step in action["runs"]["steps"]:
        assert "${{" not in step.get("run", ""), step.get("name")
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}\b", step["uses"]), f"pin {step['uses']} to a SHA"
