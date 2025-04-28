#!/bin/bash
set -euo pipefail

BATTLESHIP_DIR="ifc_examples/battleship"
readonly BATTLESHIP_DIR

BATTLESHIP_BIN="target/release/battleship"
readonly BATTLESHIP_BIN

BATTLESHIP_NO_IFC_DIR="ifc_examples/battleship-no-ifc"
readonly BATTLESHIP_NO_IFC_DIR

BATTLESHIP_NO_IFC_BIN="target/release/battleship-no-ifc"
readonly BATTLESHIP_NO_IFC_BIN

RESULT_DIR="tests/eval_results"
readonly RESULT_DIR

ANALYZE_SCRIPT_PATH="ifc_examples/benchmark_games/data/analyze.py"
readonly ANALYZE_SCRIPT_PATH

# Lines of code for Battleship.
#   - Make temp directory, move cocoon-free implementation into it
#   - Replace cocoon-free code with cocoon code
#   - Use git diff to report changes
#   - Restore current implementation from temp directory
#
# Args:
#  $1 - cocoon-free directory.
#  $2 - directory with cocoon.
function loc() {
    local no_cocoon_source_directory
    no_cocoon_source_directory="$1"

    local cocoon_source_directory
    cocoon_source_directory="$2"

    #mkdir temp
    #mv "${no_cocoon_source_directory}/"* temp
    #cp -r "${cocoon_source_directory}/"* "$no_cocoon_source_directory"
    git diff --no-index --stat -w "$no_cocoon_source_directory" "$cocoon_source_directory"
    #rm -r "$no_cocoon_source_directory/"*
    #mv temp/* "$no_cocoon_source_directory"
    #rm -r temp
}


# executable size
# cargo clean; cargo build --release
# ls -lh
# alt: (MAC) stat -f %z FILE
#            stat --format=%s FILE
function executable_size() {
    pushd "$BATTLESHIP_NO_IFC_DIR" >/dev/null 2>/dev/null
    cargo clean >/dev/null 2>/dev/null
    cargo build --release >/dev/null 2>/dev/null
    popd >/dev/null 2>/dev/null
    size_bytes=$(stat --format=%s "${BATTLESHIP_NO_IFC_BIN}")
    echo "${BATTLESHIP_NO_IFC_DIR} executable size (bytes): ${size_bytes}"

    pushd "$BATTLESHIP_DIR" >/dev/null 2>/dev/null
    cargo clean >/dev/null 2>/dev/null
    cargo build --release >/dev/null 2>/dev/null
    popd >/dev/null 2>/dev/null
    size_bytes=$(stat --format=%s "${BATTLESHIP_BIN}")
    echo "${BATTLESHIP_DIR} executable size (bytes): ${size_bytes}"
}

# Compilation times
# Method:
#   - cargo clean
#   - build release with timings
function eval_compiletime() {
    rm -f "${RESULT_DIR}/battleship-no-ifc-compile-results.csv" "${RESULT_DIR}/battleship-compile-results.csv"
    
    echo "duration (s),elapsed (s)" >> "${RESULT_DIR}/battleship-no-ifc-compile-results.csv"
    echo "duration (s),elapsed (s)" >> "${RESULT_DIR}/battleship-compile-results.csv"
    
    count=0
    while [[ $count -lt 10 ]]; do
        for dir in battleship-no-ifc battleship; do
            pushd "ifc_examples/${dir}" >/dev/null 2>/dev/null
            cargo clean
            result_file="${RESULT_DIR}/${dir}-compile-results.csv"
            start_time=$SECONDS
            duration=$(cargo build --release -Zunstable-options --timings=json 2>/dev/null | jq -r "if .target.name | test(\"battleship.*\") then .duration else empty end")
            popd >/dev/null 2>/dev/null
            elapsed=$(($SECONDS-$start_time))
            echo "${duration},${elapsed}" >> "${result_file}"
        done
        count=$count+1
    done
    pwd
    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/battleship-no-ifc-compile-results.csv"
    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/battleship-compile-results.csv"
}

function eval_runtime() {
    rm -f "${RESULT_DIR}/battleship-no-ifc-runtime-results.csv" "${RESULT_DIR}/battleship-runtime-results.csv"

    pushd "ifc_examples/battleship-no-ifc" >/dev/null 2>/dev/null
    cargo build --release >/dev/null 2>/dev/null
    popd >/dev/null 2>/dev/null

    pushd "ifc_examples/battleship" >/dev/null 2>/dev/null
    cargo build --release >/dev/null 2>/dev/null
    popd >/dev/null 2>/dev/null

    echo "run time" > "${RESULT_DIR}/battleship-no-ifc-runtime-results.csv"
    echo "run time" > "${RESULT_DIR}/battleship-runtime-results.csv"

    count=0
    while [[ $count -lt 1000 ]]; do
        CELLS=`python3 ifc_examples/battleship-no-ifc/print-cells.py`
        total_time_no_cocoon=$(echo "$CELLS" |
                                   /usr/bin/time -f '%e' "./target/release/battleship-no-ifc" 2>&1 >/dev/null)
        #CELLS=`python3 ifc_examples/battleship-no-ifc/print-cells.py`
        total_time_cocoon=$(echo "$CELLS" |
                                /usr/bin/time -f '%e' "./target/release/battleship" 2>&1 >/dev/null)
        echo "$total_time_no_cocoon" >> "${RESULT_DIR}/battleship-no-ifc-runtime-results.csv"
        echo "$total_time_cocoon" >> "${RESULT_DIR}/battleship-runtime-results.csv"
        count=$((count+1))
    done

    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/battleship-no-ifc-runtime-results.csv"
    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/battleship-runtime-results.csv"
}

echo "COMPILE TIME"
eval_compiletime
echo " "

echo "RUN TIME"
eval_runtime
echo " "

echo "LINES OF CODE"
loc "$BATTLESHIP_NO_IFC_DIR" "$BATTLESHIP_DIR"
echo " "

echo "EXECUTABLE SIZE"
executable_size
echo " "
