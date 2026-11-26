#!/bin/sh
# Phase 9 acceptance test: a full scan, and a report, inside `docker run --network none`.
#   make docker-build BUNDLE=... && make docker-test
set -eu
IMAGE="${IMAGE:-gapscan-offline}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/docker-out"
FIXTURE="$ROOT/eval/fixtures/vuln-app"
rm -rf "$OUT" && mkdir -p "$OUT"

# The container runs as the calling user so it can write /out; HOME must then be writable.
run() {
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$FIXTURE:/scan:ro" -v "$OUT:/out" "$@"
}

echo "== 1. the container really has no network"
run --entrypoint cat "$IMAGE" /proc/net/dev | awk -F: 'NR>2 {gsub(/ /,"",$1); print "interface:", $1}'
run --entrypoint python "$IMAGE" -c '
import socket
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
    raise SystemExit("FAIL: the container reached the internet")
except OSError as exc:
    print("blocked as expected:", exc)'

echo "== 2. doctor: every scanner and every dataset is present"
run "$IMAGE" doctor | tee "$OUT/doctor.txt" | grep -E "semgrep|osv|trivy|gitleaks|checkov|bandit|rules|db|cache|kb"
# The LLM rows are expected to be missing: the model is not part of this image (see the Dockerfile).
# The public image (DATA_SOURCE=fetch) carries no knowledge-base index either: it is only used by the
# optional AI review, so ALLOW_NO_KB=1 accepts that row.
SKIP="llm"
if [ "${ALLOW_NO_KB:-0}" = 1 ]; then SKIP="llm|kb index"; fi
if grep -Ev "$SKIP" "$OUT/doctor.txt" | grep -q "MISSING"; then echo "FAIL: a scanner or dataset is missing"; exit 1; fi

echo "== 3. scan"
run "$IMAGE" scan /scan -o /out/findings.json

echo "== 4. report (dashboard, SARIF, CSV, Markdown, SBOM)"
run "$IMAGE" report /out/findings.json -t /scan -o /out/report.html --json /out/report.json --exports /out/exports

echo "== 5. check the results"
python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
scan = json.loads((out / "findings.json").read_text())
status = {r["scanner"]: r["status"] for r in scan["runs"]}
assert all(s == "ok" for s in status.values()), f"scanner problems: {status}"
assert len(scan["findings"]) >= 50, f"only {len(scan['findings'])} findings"
sources = {s for f in scan["findings"] for s in f["sources"]}
assert {"semgrep", "osv", "gitleaks", "bandit"} <= sources, sources
report = json.loads((out / "report.json").read_text())
assert report["counts"]["total"] == len(scan["findings"])
assert (out / "report.html").stat().st_size > 500_000 and (out / "exports" / "report.sarif").is_file()
text = (out / "report.html").read_text() + (out / "findings.json").read_text()
assert "ghp_aB3dE5" not in text and "AKIAJ3XK7QW2" not in text, "a secret value leaked"
print(f"OFFLINE SCAN OK: {len(scan['findings'])} findings, scanners {sorted(status)}, data as of {report['freshness']['vuln_data']}")
PY
