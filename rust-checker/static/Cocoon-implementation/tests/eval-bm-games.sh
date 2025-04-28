#!/bin/bash
set -eou pipefail

# directory and trial variables
BENCHMARK_DIR="ifc_examples/benchmark_games"
readonly BENCHMARK_DIR

BENCHMARK_DIR_ORIG="ifc_examples/benchmark_games/originals"
readonly BENCHMARK_DIR_ORIG

BENCHMARK_EVAL_COMP="evaluate_build.sh"
readonly BENCHMARK_EVAL_COMP

BENCHMARK_GAMES="binary-trees fannkuch-redux fasta k-nucleotide mandelbrot n-body pidigits regex-redux spectral-norm"
readonly BENCHMARK_GAMES

BENCHMARK_EVAL_RUN="./evaluate.sh"
readonly BENCHMARK_EVAL_RUN

TRIALS=10
readonly TRIALS

RESULT_DIR="tests/eval_results"
readonly RESULT_DIR

ANALYZE_SCRIPT_PATH="ifc_examples/benchmark_games/data/analyze.py"
readonly ANALYZE_SCRIPT_PATH

# jq is a required dependency
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

# Compilation times for benchmark games (original and Cocoon)
# Method:
#   - cargo clean
#   - build release with timings
function eval_compiletime() {
    for package in $BENCHMARK_GAMES; do
        # cocoon implementation
        pushd $BENCHMARK_DIR >/dev/null 2>/dev/null
        bm_result="${RESULT_DIR}/${package}-compile-results.csv"
        "./${BENCHMARK_EVAL_COMP}" $package > "../../${bm_result}"
        popd >/dev/null 2>/dev/null
        python3 $ANALYZE_SCRIPT_PATH $bm_result

        # original implementation
        pushd $BENCHMARK_DIR_ORIG >/dev/null 2>/dev/null
        bmo_result="${RESULT_DIR}/${package}-compile-results-original.csv"
        "../${BENCHMARK_EVAL_COMP}" $package > "../../../${bmo_result}"
        popd>/dev/null 2>/dev/null
        python3 $ANALYZE_SCRIPT_PATH $bmo_result
    done
}

# Evaluate run times
function eval_runtime() {
    pushd $BENCHMARK_DIR >/dev/null 2>/dev/null
    $BENCHMARK_EVAL_RUN
    popd >/dev/null 2>/dev/null

    # report runtimes
    for package in $BENCHMARK_GAMES; do
        python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/${package}-run-results.csv"
    done
}

# Lines of code (1 trial)
#   - Make temp directory, move current implementation into it
#   - Replace current code with original code
#   - Use git diff to report changes
#   - Restore current implementation from temp directory
function loc() {
    # we don't report in paper
    pushd $BENCHMARK_DIR >/dev/null 2>/dev/null
    for dir in $BENCHMARK_GAMES; do
        #mkdir temp
        #mv $dir/src/main.rs temp
        #cp originals/$dir/src/main.rs $dir/src/
        git diff --no-index --stat -w originals/$dir/src/main.rs $dir/src/main.rs
        #rm $dir/src/main.rs
        #mv temp/main.rs $dir/src/
        #rm -d temp
    done
    popd >/dev/null 2>/dev/null
}

# executable size
# cargo clean; cargo build --release
# ls -lh
# alt: (MAC) stat -f %z FILE
#            stat --format=%s FILE
function executable_size() {
    # benchmark games
    for package in $BENCHMARK_GAMES; do
        pushd "${BENCHMARK_DIR}/${package}" >/dev/null 2>/dev/null
        cargo clean >/dev/null 2>/dev/null
        cargo build --release >/dev/null 2>/dev/null
        popd >/dev/null 2>/dev/null
        size_bytes=$(stat --format=%s target/release/${package})
        echo "${package} executable size (bytes): ${size_bytes}"
    done
}

ensure_jq
# Submodule update will fail if there aren't .git files; ignore the failure if so
set +e
git submodule update --init --recursive >/dev/null 2>/dev/null
set -e

echo "COMPILE TIME"
eval_compiletime
echo  " "

echo "RUN TIME"
eval_runtime
echo " "

echo "LINES OF CODE"
loc
echo " "

echo "EXECUTABLE SIZE"
executable_size