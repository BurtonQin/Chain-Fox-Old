#!/bin/bash
set -eou pipefail

# directory and trial variables
COCOON_SPOTIFY_DIR="ifc_examples/spotify-tui/spotify-tui-cocoon/"
readonly COCOON_SPOTIFY_DIR

ORIG_SPOTIFY_DIR="ifc_examples/spotify-tui/spotify-tui-original/"
readonly ORIG_SPOTIFY_DIR

SPOTIFY_BIN="target/release/spt"
readonly SPOTIFY_BIN

EVAL_SPOTIFY_SCRIPT_DIR="ifc_examples/spotify-tui/"
readonly EVAL_SPOTIFY_SCRIPT_DIR

EVAL_SPOTIFY_SCRIPT="./eval_spotify.sh"
readonly EVAL_SPOTIFY_SCRIPT

RUNTIME_TRIALS=10000
readonly RUNTIME_TRIALS

COMPILETIME_TRIALS=10
readonly COMPILETIME_TRIALS

RESULT_DIR="tests/eval_results"
readonly RESULT_DIR

ANALYZE_SCRIPT_PATH="ifc_examples/benchmark_games/data/analyze.py"
readonly ANALYZE_SCRIPT_PATH

# Compilation times for Spotify-tui (original and Cocoon)
# Method:
#   - cargo clean
#   - build release with timings
function eval_compiletime() {
    echo "COMPILE TIME"
    # spotify-tui
    rm -f "${RESULT_DIR}/spotify-tui-original-compile-results.csv" "${RESULT_DIR}/spotify-tui-cocoon-compile-results.csv"
    count=0

    echo "duration (s),elapsed (s)" >> "${RESULT_DIR}/spotify-tui-original-compile-results.csv"
    echo "duration (s),elapsed (s)" >> "${RESULT_DIR}/spotify-tui-cocoon-compile-results.csv"

    while [[ $count -lt $COMPILETIME_TRIALS ]]; do
        for dir in spotify-tui-original spotify-tui-cocoon; do
            pushd "ifc_examples/spotify-tui/$dir" >/dev/null 2>/dev/null
            cargo clean
            result_file="${RESULT_DIR}/${dir}-compile-results.csv"
            package_name=$(basename "$dir")
            start_time=$SECONDS
            duration=$(cargo build --release -Zunstable-options --timings=json 2>/dev/null | jq -r "if .target.name == \"spt\" then .duration else empty end")
            popd >/dev/null 2>/dev/null
            elapsed=$(($SECONDS-$start_time))
            echo "${duration},${elapsed}" >> "${result_file}"
        done
        count=$((count+1))
    done
    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/spotify-tui-original-compile-results.csv"
    python3 $ANALYZE_SCRIPT_PATH "${RESULT_DIR}/spotify-tui-cocoon-compile-results.csv"
}

# Evaluate run times for spotify-tui
function eval_runtime() {
    echo "RUN TIME"
    pushd $EVAL_SPOTIFY_SCRIPT_DIR >/dev/null 2>/dev/null
    $EVAL_SPOTIFY_SCRIPT $RUNTIME_TRIALS
    popd >/dev/null 2>/dev/null
}

# Lines of code (1 trial) for spotify-tui
#   - Make temp directory, move current implementation into it
#   - Replace current code with original code
#   - Use git diff to report changes
#   - Restore current implementation from temp directory
function loc() {
    echo "LINES OF CODE"
    #mkdir temp
    #mv $COCOON_SPOTIFY_DIR/src/main.rs $COCOON_SPOTIFY_DIR/src/config.rs $COCOON_SPOTIFY_DIR/src/redirect_uri.rs $COCOON_SPOTIFY_DIR/src/network.rs temp
    #cp $ORIG_SPOTIFY_DIR/src/main.rs $ORIG_SPOTIFY_DIR/src/config.rs $ORIG_SPOTIFY_DIR/src/redirect_uri.rs $ORIG_SPOTIFY_DIR/src/network.rs $COCOON_SPOTIFY_DIR/src/
    git diff --no-index --stat -w $COCOON_SPOTIFY_DIR/src $ORIG_SPOTIFY_DIR/src
    #rm $COCOON_SPOTIFY_DIR/src/main.rs $COCOON_SPOTIFY_DIR/src/config.rs $COCOON_SPOTIFY_DIR/src/redirect_uri.rs $COCOON_SPOTIFY_DIR/src/network.rs
    # restore temp files
    #mv temp/* $COCOON_SPOTIFY_DIR/src/
    #rm -d temp
}

# executable size
# cargo clean; cargo build --release
# ls -lh
# alt: (MAC) stat -f %z FILE
#            stat --format=%s FILE
function executable_size() {
    echo "EXECUTABLE SIZE"
    for dir in $COCOON_SPOTIFY_DIR $ORIG_SPOTIFY_DIR; do
        pushd $dir >/dev/null 2>/dev/null
        cargo clean >/dev/null 2>/dev/null
        cargo build --release >/dev/null 2>/dev/null
        popd >/dev/null 2>/dev/null
        size_bytes=$(stat --format=%s ${SPOTIFY_BIN})
        echo "${dir} executable size (bytes): ${size_bytes}"
    done
}

eval_compiletime
echo  " "

eval_runtime
echo " "

loc
echo " "

executable_size
