# Evaluation of Cocoon
This directory contains various scripts to evaluate the run and compile times, executable size, and lines of code (LOC) changed for the Servo, Spotify-TUI, Battleship, and Benchmark Games case studies presented in the paper. 

## Scripts
The `eval.sh` script is the most general and will reproduce the results from the paper with one command. Most of the other scripts are called from `eval.sh` and specialize in one type of evaluation or a specific case study. 
* `eval-bm-games.sh` runs all evaluations (compile and run times, LOC, and executable size) for the Benchmark Games.
* `eval-battleship.sh` runs all evaluations for Battleship.
* `eval-spt.sh` runs all evaluations for Spotify-TUI.
* `eval.sh` runs all evaluations for all case studies.
* `test-all.sh` runs the internal Cocoon examples and ensures they generate expected output.
