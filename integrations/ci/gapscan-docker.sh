#!/usr/bin/env bash
# `gapscan` on PATH, run from the public image: the GitHub Action (action.yml, engine: docker) puts
# this script on PATH as `gapscan`. The workspace is mounted at the same path so relative paths,
# git history and the output files all line up; the container runs as the runner's user so the files
# it writes belong to the job.
#
#   GAPSCAN_IMAGE           image to run (default ghcr.io/shawaf/gapscan:latest)
#   GAPSCAN_DOCKER_NETWORK  none (default) for scans, bridge for steps that call an API
#   GAPSCAN_SCM_TOKEN       passed through for `gapscan ci comment` and `gapscan pr`
set -euo pipefail
image="${GAPSCAN_IMAGE:-ghcr.io/shawaf/gapscan:latest}"
network="${GAPSCAN_DOCKER_NETWORK:-none}"
workspace="${GITHUB_WORKSPACE:-$PWD}"
args=(--rm --network "$network" --user "$(id -u):$(id -g)" -e HOME=/tmp
      -v "$workspace:$workspace" -w "$PWD")
if [ -n "${GAPSCAN_SCM_TOKEN:-}" ]; then args+=(-e GAPSCAN_SCM_TOKEN); fi
exec docker run "${args[@]}" "$image" "$@"
