The evaluation scripts output raw results in this directory.

## Directory Structure
- `battleship_samples`: sample output files for script `eval-battleship.sh`
- `bm_games_samples`: sample output files for script `eval-bm-games.sh`
- `servo_samples`: sample output files for Servo evaluation. To run this evaluation, see `info-flow-library/ifc_examples/servo/README.md`.
- `spotify-tui_samples`: sample output files for script `eval-spt.sh`. 

## Sample Outputs
This directory also includes sample output files for each evaluation script. 

### Spotify-TUI
`spotify-tui_samples/spotify-results-sample.txt` shows the output from running `eval-spt.sh`. The `.txt` file has the following format.
```
COMPILE TIME
tests/eval-results/spotify-tui-original-compile-results.csv: duration (s): [mean] +- [95% confidence interval]
tests/eval-results/spotify-tui-original-compile-results.csv: elapsed (s): [mean] +- [95% confidence interval]
tests/eval-results/spotify-tui-cocoon-compile-results.csv: duration (s): [mean] +- [95% confidence interval]
tests/eval-results/spotify-tui-cocoon-compile-results.csv: elapsed (s): [mean] +- [95% confidence interval]

RUN TIME
Running 10000 trials...
spotify-tui-original-results.csv: elapsed (ns): [mean] +- [95% confidence interval]
spotfiy-tui-cocoon-results.csv elapsed (ns): [mean] +- [95% confidence interval]
Finished 10000 trials...

LINES OF CODE
[relative path to modified file]  |  [number of lines changed] +-
[...]
[#] files changed, [#] insertions(+), [#] deletions(-)

EXECUTABLE SIZE
ifc_examples/spotify-tui/spotify-tui-cocoon/ executable size (bytes): [size]
ifc_examples/spotify-tui/spotify-tui-original/ executable size (bytes): [size]
```

`eval-spt.sh` also generates files similar to `spotify-tui_samples/spotify-tui-cocoon-compile-results-sample.csv` and `spotify-tui_samples/spotify-tui-original-results-sample.csv`. The former gives the output from compile time trials for the Cocoon-integrated version of Spotify TUI while the latter gives the compile time trials for the original implementation. Both files have the following format. 
```
duration (s),elapsed (s)
[#],[#]
[...]
```

### Battleship
`battleship_samples/` contains the output files from running `eval-battleship.sh`. `battleship_samples/battleship-results-sample.txt` gives the console output from the script and has the following format. 
```
COMPILE TIME
[file path]/battleship-no-ifc-compile-results.csv: duration: [mean] +- [95% confidence interval]
[file path]/battleship-no-ifc-compile-results.csv: elapsed (s): [mean] +- [95% confidence interval]
[file path]/battleship-compile-results.csv: duration: [mean] +- [95% confidence interval]
[file path]/battleship-compile-results.csv: duration (s): [mean] +- [95% confidence interval]

RUN TIME
tests/eval_results/battleship-no-ifc-runtime-results.csv: run time: [mean] +- [95% confidence interval]
test/eval_results/battleship-runtime-results.csv: run time: [mean] +- [95% confidence interval]

LINES OF CODE
[relative file path]   |  [number of lines modified] +-
[...]
[#] files changed, [#] insertions(+), [#] deletions(-)

EXECUTABLE SIZE
ifc_examples/battleship-no-ifc executable size (bytes): [size]
ifc_examples/battleship executable size (bytes): [size]
```

`eval-battleship.sh` also generates four output files, samples of which can be found in `tests/eval_results/battleship_samples/`. `battleship-compile-results-sample.csv` and `battleship-no-ifc-compile-results-sample.csv` give the compile times from each trial for Battleship with and without Cocoon integration, respectively. Both files have the following format. 
```
duration (s),elapsed (s)
[#],[#]
[...]
```

`battleship-runtime-results-sample.csv` and `battleship-no-ifc-runtime-results-sample.csv` give the run time for each trial for the Cocoon and original implementations, respectively. The format for these files is given below. 
```
run time
[#]
[...]
```

### Servo
Due to its size, Servo is out-of-tree. To run the Servo evaluation, see `info-flow-library/ifc_examples/servo/README.md`. The evaluation described there produces four files, for which samples are given in `tests/eval_results/servo_samples`. `modified_builds-sample.csv` and `original_builds-sample.csv` give the raw compile time trials results for the Cocoon-integrated and original implementations, respectively. `modified_tests-sample.csv` and `original_tests-sample.csv` give the run time trials. All four files have format:
```
time,max_rss
[Trial 1: time (s)],[maximum memory usage (KB)]
[Trial 2: time (s)],[maximum memory usage (KB)]
[...]
```

### Benchmark Games
The sample output files for the Benchmark Games are located in `bm_games_samples/`. `bm_games_samples/bm-games-results-samples.txt` gives sample output from running `eval-bm-games.sh` and has the following format. 
```
COMPILE TIME
tests/[package name]-compile-results.csv: compile_time_package: [mean] +- [95% confidence interval]
tests/[package name]-compile-results.csv: compile_time_total: [mean] +- [95% confidence interval]
[...]

RUN TIME
Benchmarking [package name]: (1 / 10)
Benchmarking [package name]: (2 / 20)
[...]
Start benchmark for original implementation.
Benchmarking [package name]: (1 / 10)
Benchmarking [package name]: (2 / 20)
[...]

LINES OF CODE
[relative file path]   |  [number of lines modified] +-
[...]
[#] files changed, [#] insertions(+), [#] deletions(-)

EXECUTABLE SIZE
[package name] executable size (bytes): [size]
[...]
```

For each package, four files are produced: `[package name]-compile-results-original-sample.csv`, `[package  name]-compile-results-sample.csv`, `[package name]-run-results-sample.csv`, and `originals/[package name]-sample.csv`. The first two files give the output of running compile time trials for the original and Cocoon implementations, respectively. These files have the following format. 
```
compile_time_package,compile_time_total
[#],[#]
[...]
```

`[package name]-run-results-sample.csv` has the run time trial results for the Cocoon-integrated implementation, and `originals/[package name]-sample.csv` contains run time results for the original implementation. These files have the following format, where `max_rss` corresponds to the maximum memory usage in KB. 
```
time,max_rss
[#],[#]
[...]
```
