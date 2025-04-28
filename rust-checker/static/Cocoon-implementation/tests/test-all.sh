#!/bin/bash

# Must be run from parent directory (info-flow-library)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

one-test() {
    pushd $1 > /dev/null
    if [ -z "$2" ]
    then
        NAME=`basename $PWD`
    else
        NAME=$2
    fi

    set +e

    if [ -z "$3" ]
    then
      echo -n Testing $OP on $NAME"... "
      cargo $OP &> /dev/null
    else
      echo -n Running $NAME"... "
      $3 &> /dev/null
    fi

    if [ $? -eq 0 ]
    then
        echo -e ${GREEN}PASSED${NC}
    else
        echo -e ${RED}FAILED${NC} #\(ran "cargo $OP" in $PWD\)
    fi

    set -e

    popd > /dev/null
}

if [ $# -eq 0 ]
then
    echo test-all.sh OPERATION
    echo "OPERATION is clean, check, build, or run (or any cargo command, actually)"
    exit
fi

OP="$*"

one-test ifc_examples/counter_examples
one-test ifc_examples/millionaires
one-test ifc_examples/paper_calendar
#one-test ifc_examples/deprecated_examples/paper_examples
one-test ifc_examples/overloaded_operators


if [[ "$OP" == *"run"* ]]
then
  # echo 'Skipping running battleship since it requires stdin; see ifc_examples/battleship/README.md'

  python3 ifc_examples/battleship/print-cells.py | one-test ifc_examples/battleship

  echo 'Skipping running benchmark_games since they require arguments and stdin; use benchmark_games/evaluate.sh instead'
else

  one-test ifc_examples/battleship

  for i in binary-trees fannkuch-redux fasta k-nucleotide mandelbrot n-body pidigits regex-redux spectral-norm
  do
      one-test ifc_examples/benchmark_games/$i
      one-test ifc_examples/benchmark_games/originals/$i originals/$i
  done
fi

one-test ifc_examples/spotify-tui/spotify-tui-cocoon
one-test ifc_examples/spotify-tui/spotify-tui-original

one-test ifc_library/macros macro-tests "tests/autotest.sh"
