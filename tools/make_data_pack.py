"""Build the security-data pack that the setup wizard downloads, and pin it in the manifest.

The pack is an ordinary offline bundle (what `gapscan bundle` makes) built from the data already on this machine, so run
`gapscan bundle` once on a connected machine first (or refresh the data another way). Publishing is a separate, deliberate
step: upload the file to wherever the manifest will point, then pin it.

    uv run python tools/make_data_pack.py --out dist/gapscan-data-2026-10-05.tar.gz
    uv run python tools/make_data_pack.py --out dist/gapscan-data-2026-10-05.tar.gz --url https://host/gapscan-data-2026-10-05.tar.gz
    uv run python tools/make_data_pack.py --out ... --url ... --manifest other-manifest.json    # write a different manifest

With --url the pack entry (size and sha256 included) is written into the manifest; without it only the file is built.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from gapscan.config import load_config
from gapscan.offline.bundle import BundleOptions, build_bundle
from gapscan.runtime.download import sha256_file
from gapscan.runtime.manifest import MANIFEST_PATH


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--url",
        help="where the file will be downloaded from (HTTPS); pins the pack in the manifest",
    )
    ap.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = ap.parse_args()
    cfg = load_config(None)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_bundle(cfg.data.dir, args.out, BundleOptions(compress=True))
    size, digest = args.out.stat().st_size, sha256_file(args.out)
    print(f"wrote {args.out} ({size / 1e6:.0f} MB, {len(manifest.files)} files), sha256 {digest}")
    print("snapshots:", manifest.snapshots)
    if not args.url:
        print("not pinned (no --url). Upload the file, then run again with --url to pin it.")
        return
    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    data["packs"] = [p for p in data["packs"] if p["kind"] != "data"]
    data["packs"].append({
        "id": f"data-{datetime.now(UTC).strftime('%Y-%m-%d')}", "kind": "data", "url": args.url, "size": size, "sha256": digest,
        "filename": args.out.name, "version": manifest.created_at[:10], "note": "Security data: vulnerability databases, advisories, knowledge base.",
    })  # fmt: skip
    args.manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"pinned in {args.manifest}")


if __name__ == "__main__":
    main()
