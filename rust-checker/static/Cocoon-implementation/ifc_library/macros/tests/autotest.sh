#!/bin/bash

# Please run shellcheck to detect common script errors if you edit this file.

set -eou pipefail

GIT_TOP=$(pwd)/../..
readonly GIT_TOP

MACROS_DIR="${GIT_TOP}/ifc_library/macros"
readonly MACROS_DIR

MACROS_TESTS_DIR="${MACROS_DIR}/tests"
readonly MACROS_TESTS_DIR

MACROS_RELEASE_DIR="${MACROS_DIR}/target/release"
readonly MACROS_RELEASE_DIR

STRUCTS_DIR="${GIT_TOP}/ifc_library/secret_structs"
readonly STRUCTS_DIR

STRUCTS_RELEASE_DIR="${STRUCTS_DIR}/target/release"
readonly MACROS_RELEASE_DIR

LIBRARY_EXT=".so"
if [[ "$(uname)" = "Darwin" ]]; then
  LIBRARY_EXT=".dylib"
fi
readonly LIBRARY_EXT

INDENTATION=""

EXIT_STATUS=0

function indent() {
  INDENTATION="  ${INDENTATION}"
}

function unindent() {
  INDENTATION=$(echo "${INDENTATION}" | cut -c 3-)
}

function with_indent() {
  indent
  "$@"
  unindent
}

function iecho() {
  echo "${INDENTATION}" "$@"
}

function build_crate() {
  local crate_path
  crate_path="$1"
  
  pushd "${crate_path}" >/dev/null 2>/dev/null

  set +e
  local build_output exit_code
  build_output=$(cargo build --release --lib 2>&1)
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne 0 ]]; then
    iecho "Building ${crate_path} failed. Output:"
    iecho "${build_output}"
    popd >/dev/null 2>/dev/null
    exit 1
  fi

  popd >/dev/null 2>/dev/null
}

function rust_src_filename_to_test_filename() {
  local rust_src_filename
  rust_src_filename=$1
  echo "${rust_src_filename//.rs/}"
}

function compile_should_fail() {
  local rust_src_filename
  rust_src_filename="$1"
  [[ "${rust_src_filename}" =~ "no_compile".* ]] || [[ "${rust_src_filename}" =~ "not_yet_supported".* ]]
}

function build_test_files() {
  pushd "${MACROS_TESTS_DIR}" >/dev/null 2>/dev/null

  shopt -s nullglob
  for filename in *.rs; do
    iecho "Building ${filename}..."
    local outputname
    outputname=$(rust_src_filename_to_test_filename "${filename}")

    set +e
    local compile_output exit_code
    #compile_output=$(rustc --extern secret_macros=${MACROS_RELEASE_DIR}/libsecret_macros${LIBRARY_EXT} -L ${STRUCTS_RELEASE_DIR} -L ${STRUCTS_RELEASE_DIR}/deps "${filename}" -o "${outputname}" 2>&1)
    compile_output=$(rustc --extern secret_macros=${MACROS_RELEASE_DIR}/libsecret_macros${LIBRARY_EXT} -L ${STRUCTS_RELEASE_DIR} "${filename}" -o "${outputname}" 2>&1)
    exit_code=$?
    set -e

    if compile_should_fail "${filename}" && [[ "${exit_code}" -eq 0 ]]; then
      iecho "TEST FAILED: ${filename}"
      iecho "The file ${filename} compiled, but a compilation error is expected."
      iecho
      EXIT_STATUS=1
    elif ! compile_should_fail "${filename}" && [[ "${exit_code}" -ne 0 ]]; then
      iecho "TEST FAILED: ${filename}"
      iecho "Output:"
      iecho "${compile_output}"
      iecho
      EXIT_STATUS=1
    elif compile_should_fail "${filename}"; then
      iecho "TEST PASSED: ${filename} did NOT compile, as expected."
    fi

  done
  shopt -u nullglob

  popd >/dev/null 2>/dev/null
}

function run_tests() {
  pushd "${MACROS_TESTS_DIR}" >/dev/null 2>/dev/null

  shopt -s nullglob
  for filename in *.rs; do
    local test_filename test_output test_exit_status
    test_filename=$(rust_src_filename_to_test_filename "${filename}")
    if [[ ! -e "${test_filename}" ]] || compile_should_fail "${filename}.rs"; then
      continue
    fi

    set +e
    test_output=$(./"${test_filename}" 2>&1)
    test_exit_status=$?
    set -e

    if [[ "${test_exit_status}" -ne 0 ]]; then
      iecho "TEST FAILED: ${filename}"
      iecho "Output:"
      iecho "${test_output}"
      iecho
      EXIT_STATUS=1
    else
      iecho "TEST PASSED: ${filename}"
    fi
  done
  shopt -u nullglob

  popd >/dev/null 2>/dev/null
}

function is_binary() {
  local filename
  filename="$1"
  [[ "$(file --mime-encoding "${filename}")" =~ .*": binary" ]] && [[ "$(wc -c "${filename}" | awk '// { print $1 }')" -gt 1 ]]
}

function rm_test_binaries() {
  pushd "${MACROS_TESTS_DIR}" >/dev/null 2>/dev/null
  for file in *; do
    if is_binary "${file}"; then
      rm "${file}"
    fi
  done
  popd >/dev/null 2>/dev/null
}

iecho "Building macros crate..."
with_indent \
  build_crate "${MACROS_DIR}"

iecho "Building secret structs crate..."
with_indent \
  build_crate "${STRUCTS_DIR}"

iecho "Building test files..."
with_indent \
  build_test_files

iecho "Running tests..."
with_indent \
  run_tests

rm_test_binaries
exit "${EXIT_STATUS}"