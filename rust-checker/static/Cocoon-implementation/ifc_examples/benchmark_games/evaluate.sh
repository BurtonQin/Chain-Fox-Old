#!/bin/bash

set -eou pipefail

ORIGINAL_DIRNAME="originals"
readonly ORIGINAL_DIRNAME

#REPO=$(git rev-parse --show-toplevel)
REPO=$(pwd)/../..
readonly REPO

ORIGINAL_DIR="${REPO}/ifc_examples/benchmark_games/${ORIGINAL_DIRNAME}"
readonly ORIGINAL_DIR

DATA_DIR="data"
readonly DATA_DIR

EXPERIMENT_COUNT=10
readonly EXPERIMENT_COUNT

RESULT_DIR="${REPO}/tests/eval_results"
readonly RESULT_DIR

if [[ $# -eq 1 ]]; then
  ONLY_BENCHMARK=$1
fi

function benchmark_directories() {
  if [[ -n "${ONLY_BENCHMARK:-}" ]]; then
    echo "$ONLY_BENCHMARK"
  else
    for filename in *; do
      if [[ -d "$filename" ]] && [[ "$filename" != "$ORIGINAL_DIRNAME" ]] && [[ "$filename" != "$DATA_DIR" ]] ; then
        echo "$filename"
      fi
    done
  fi
}

function do_benchmark() {
  local program_name="$1"
  local arg="$2"
  local result_file="$3"
  local binary_name="${REPO}/target/release/${program_name}"
  echo "time,max_rss" > "${result_file}"

  local count=0
  while [[ $count -lt $EXPERIMENT_COUNT ]]; do
    count=$((count+1))
    echo "Benchmarking ${program_name}: (${count} / ${EXPERIMENT_COUNT})"
    gawk_script=$(cat <<EOF
    /.* real .* user .* sys/ {
      time=\$3;
    }
    /.* maximum resident set size/ {
      rss=\$1;
    }
    /time: .* rss: .*/ {
      time=\$2;
      rss=\$4
    }
    END {
      print(time","rss);
    }
EOF
)
    if [[ -e stdin ]]; then
      /usr/bin/time "${time_args}" "${binary_name}" "${arg}" < stdin 2>&1 >/dev/null | \
        gawk "${gawk_script}"  >> "${result_file}"
    else
      /usr/bin/time "${time_args}" "${binary_name}" "${arg}" 2>&1 >/dev/null | \
       gawk "${gawk_script}"  >> "${result_file}"
    fi
  done
}

function ensure_stdin() {
  local program_name=$1
  case "$program_name" in
    k-nucleotide)
      pushd "${ORIGINAL_DIR}/fasta" 2>/dev/null >/dev/null
      cargo build --release 2>/dev/null >/dev/null
      popd 2>/dev/null >/dev/null
      "${ORIGINAL_DIR}/fasta/target/release/fasta" 25000000 > stdin
      ;;
  esac
}

time_args=""
case $(uname) in
  Linux)
    time_args=--format='time: %e rss: %M'
    ;;
  Darwin)
    time_args="-l"
    ;;
  *)
    echo "unrecognized system"
    exit 1
    ;;
esac

# Build & run.
for dir in $(benchmark_directories); do
  if [[ "$dir" = "dependencies" ]]; then
    continue
  fi

  pushd "$dir" >/dev/null 2>/dev/null
  cargo build --release 2>/dev/null >/dev/null
  program_name=$(basename -- "$dir")
  result_file="${RESULT_DIR}/${program_name}-run-results.csv"
  arg=$(cat arg)

  should_remove_stdin=0
  if [[ ! -e stdin ]]; then
    should_remove_stdin=1
  fi

  ensure_stdin "$program_name"
  do_benchmark "$program_name" "$arg" "$result_file"
  popd >/dev/null 2>/dev/null

  echo "Start benchmark for original implementation."

  original_dir="${ORIGINAL_DIR}/${program_name}"
  if [[ -e "${dir}/stdin" ]]; then
    ln -s "$(pwd)/${dir}/stdin" "${original_dir}/stdin"
  fi

  pushd "$original_dir" >/dev/null 2>/dev/null
  cargo build --release 2>/dev/null >/dev/null
  result_file="${RESULT_DIR}/bm_games_samples/originals/${program_name}.csv"
  do_benchmark "$program_name" "$arg" "$result_file"
  popd >/dev/null 2>/dev/null

  echo ""

  if [[ -e "${dir}/stdin" ]]; then
    rm "${original_dir}/stdin"
  fi

  if [[ $should_remove_stdin = 1 ]]; then
    rm -f "${dir}/stdin"
  fi
done
