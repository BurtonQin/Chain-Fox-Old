#!/bin/bash

set -eou pipefail

GIT_TOP=$(git rev-parse --show-toplevel)
readonly GIT_TOP

docker container run                      \
  --rm                                    \
  -v "${GIT_TOP}":/src/                   \
  -w /src/ifc_library/macros/             \
  rust:1.63.0-buster                      \
  bash -c 'rustup default nightly && tests/autotest.sh'
