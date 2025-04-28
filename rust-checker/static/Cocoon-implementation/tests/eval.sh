#!/bin/bash
set -eou pipefail

# Does not include Servo evaluation as it is out-of-tree.
# See ifc_examples/servo/README.md for evaluation instructions. 

BENCHMARK_GAMES="tests/eval-bm-games.sh"
readonly BENCHMARK_GAMES

SPOTIFY_TUI="tests/eval-spt.sh"
readonly SPOTIFY_TUI

BATTLESHIP="tests/eval-battleship.sh"
readonly BATTLESHIP

echo "SPOTIFY-TUI"
$SPOTIFY_TUI
echo " "

echo "BENCHMARK GAMES"
$BENCHMARK_GAMES
echo " "

echo "BATTLESHIP"
$BATTLESHIP
echo " "