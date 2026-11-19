"""Validate the CI templates and pre-commit files against their official JSON schemas.

A development check (it downloads the schemas, so it is not part of `make test`):

    uv run --with jsonschema python tools/validate_ci.py [--cache data/schemas]

Schemas: GitHub Actions and pre-commit from SchemaStore, GitLab CI from gitlab-org/gitlab, Azure
Pipelines from microsoft/azure-pipelines-vscode. For GitHub workflows, also run `actionlint`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import yaml
from jsonschema import Draft7Validator, validators

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "github-workflow.json": "https://json.schemastore.org/github-workflow.json",
    "gitlab-ci.json": "https://gitlab.com/gitlab-org/gitlab/-/raw/master/app/assets/javascripts/editor/schema/ci.json",
    "azure-pipelines.json": "https://raw.githubusercontent.com/microsoft/azure-pipelines-vscode/main/service-schema.json",
    "pre-commit-config.json": "https://json.schemastore.org/pre-commit-config.json",
    "pre-commit-hooks.json": "https://json.schemastore.org/pre-commit-hooks.json",
}
FILES = [
    ("integrations/ci/github-actions.yml", "github-workflow.json"),
    ("integrations/ci/gitlab-ci.yml", "gitlab-ci.json"),
    ("integrations/ci/azure-pipelines.yml", "azure-pipelines.json"),
    (".pre-commit-config.yaml", "pre-commit-config.json"),
    (".pre-commit-hooks.yaml", "pre-commit-hooks.json"),
]


def schema(cache: Path, name: str) -> dict[str, Any]:
    path = cache / name
    if not path.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        r = httpx.get(SCHEMAS[name], follow_redirects=True, timeout=60)
        r.raise_for_status()
        path.write_bytes(r.content)
    return json.loads(path.read_text("utf-8-sig"))


def load(doc: Path) -> Any:
    # Azure Pipelines types every scalar as a string in its schema; GitHub's `on:` key is YAML 1.1 `True`.
    loader = yaml.BaseLoader if "azure" in doc.name else yaml.SafeLoader
    data = yaml.load(doc.read_text(), Loader=loader)  # noqa: S506 - safe/base loaders only
    if isinstance(data, dict) and True in data:
        data["on"] = data.pop(True)
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", type=Path, default=ROOT / "data/schemas")
    args = ap.parse_args()
    failed = 0
    for rel, name in FILES:
        s = schema(args.cache, name)
        v = validators.validator_for(s, default=Draft7Validator)(s)
        errors = list(v.iter_errors(load(ROOT / rel)))
        print(f"{rel}: {'OK' if not errors else f'{len(errors)} errors'}")
        for e in errors[:10]:
            print(f"    {list(e.absolute_path)} {e.message[:200]}")
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
