# Benchmarks
These Benchmarks are adapted from [the programming language benchmark games](https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/rust.html) to measure our library's overhead.

## Initializing
Prior to running benchmarks, you must run the command `git submodule update --init --recursive`.

## Evaluating
Run all benchmarks with the command `./evaluate.sh`. This writes data to the `data` directory.
Analyze the data with the `./data/analyze.py` script.

For example, I analyze the `fannkuch-redux` benchmark with the command `./evaluate.sh fannkuch-redux`.

## Evaluate Compile Time
Run the command `./evaluate_build.sh [path to crate]`.
This command writes the results as a CSV to stdout.
You can compute confidence intervals on the results using
the `./data/analyze.py` script.

## Benchmarks
All benchmarks use the fastest version of the available Rust implementations, unless otherwise noted.

- [fannkuch-redux Rust #6](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/fannkuchredux-rust-6.html). Test with arg 12.
- [n-body rust #9](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/nbody-rust-9.html). Test with arg 50000000.
- [spectralnorm rust #5](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/spectralnorm-rust-5.html). Test with arg 5500.
- [mandelbrot rust #6](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/mandelbrot-rust-6.html). Test with arg 16000.
- [pidigits rust #4](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/pidigits-rust-4.html). Test with arg 10000.
- [fasta rust #7](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/fasta-rust-7.html). Test with arg 25000000.
- [binary-trees rust #5](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/binarytrees-rust-5.html). Test with arg 21.
- [regex-redux rust #6](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/regexredux-rust-6.html). Test with arg 0 and stdin from stdin file.
- [k-nucleotide rust #8](https://benchmarksgame-team.pages.debian.net/benchmarksgame/program/knucleotide-rust-8.html). Test with arg 0 and stdin from fasta 25000000. Note that this is not the fastest implementation of `k-nucleotide`. The reason is that the fastest version of `k-nucleotide` depends on `futures==0.2.x` but this release has been yanked (i.e., permanently deleted) from the upstream repository.
