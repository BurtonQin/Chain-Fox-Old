#!/usr/bin/env bash

# this script's location
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z "$1" ]; then
        echo "No detecting directory is provided"
	echo "Usage: ./detect.sh DIRNAME"
        exit 1
fi
# Build atomvchecker
cargo build
# For development of atomvchecker use debug build
export RUSTC_WRAPPER=${PWD}/target/debug/atomvchecker
# For usage use release
# cargo build --release
# export RUSTC_WRAPPER=${PWD}/target/release/atomvchecker
export RUST_BACKTRACE=full
export ATOMVCHECKER_LOG=debug
# To only detect RUSTSEC-2022-0006,RUSTSEC-2022-0029
# export ATOMVCHECKER_FLAGS="--detector-kind atomicity_violation --crate-name-list RUSTSEC-2022-0006,RUSTSEC-2022-0029"
# To skip detecting RUSTSEC-2022-0006 or RUSTSEC-2022-0029
# export ATOMVCHECKER_FLAGS="--detector-kind atomicity_violation --blacklist-mode --crate-name-list RUSTSEC-2022-0006,RUSTSEC-2022-0029"
# or shorter
# export ATOMVCHECKER_FLAGS="-k atomicity_violation -b -l RUSTSEC-2022-0006,RUSTSEC-2022-0029"
# export ATOMVCHECKER_FLAGS="-k atomicity_violation -b -l cc"
export ATOMVCHECKER_FLAGS="-k atomicity_violation -b -l" # cc thread_local-rs

# Find all Cargo.tomls recursively under the detecting directory
# and record them in cargo_dir.txt
cargo_dir_file=$(realpath $DIR/cargo_dir.txt) # "/home/wangcheng/AtomVChecker/cargo_dir.txt" # $(realpath $DIR/cargo_dir.txt)  "/Users/wangcheng/Downloads/AtomVChecker/cargo_dir.txt"
rm -f $cargo_dir_file
touch $cargo_dir_file

pushd "$1" > /dev/null
cargo clean
cargo_tomls=$(find . -name "Cargo.toml")
for cargo_toml in ${cargo_tomls[@]}
do
        echo $(dirname $cargo_toml) >> $cargo_dir_file
done

IFS=$'\n' read -d '' -r -a lines < ${cargo_dir_file}
for cargo_dir in ${lines[@]}
do
        pushd ${cargo_dir} > /dev/null
        cargo build
        popd > /dev/null
done
popd > /dev/null

rm -f $cargo_dir_file
