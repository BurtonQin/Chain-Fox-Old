#!/bin/bash

# Dependencies:
#  - jq
#
# Usage:
#  ./evaluate_build.sh [path to package]
#
# Assumptions:
#   The package name matches the directory.
#   The package builds successfully.

set -eou pipefail

NUM_EXPERIMENTS=10
readonly NUM_EXPERIMENTS

function ensure_jq() {
  set +e
  echo '' | jq >/dev/null 2>/dev/null
  local exit_status=$?
  set -e
  if [[ $exit_status -ne 0 ]]; then
    echo "Please install jq." >&2
    exit 1
  fi
}

function benchmark_compilation() {
  local package_dir="$1"
  pushd "$package_dir" >/dev/null 2>/dev/null
  cargo clean >/dev/null 2>/dev/null
  package_name=$(basename "$package_dir")
  start_time=$SECONDS
  duration=$(cargo build --release -Zunstable-options --timings=json 2>/dev/null | \
    jq -r "if .target.name == \"${package_name}\" then .duration else empty end")
  popd >/dev/null 2>/dev/null
  elapsed=$(($SECONDS-$start_time))
  echo "${duration},${elapsed}"
}

if [[ $# -ne 1 ]]; then
  echo "usage: $0 [path to package]" >&2
  exit 1
fi

PACKAGE_PATH=$1
readonly PACKAGE_PATH

ensure_jq

echo "compile_time_package,compile_time_total"
count=0
while [[ $count -lt $NUM_EXPERIMENTS ]]; do
  benchmark_compilation "$PACKAGE_PATH"
  count=$((count+1))
done
