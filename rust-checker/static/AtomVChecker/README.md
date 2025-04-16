# AtomVChecker
Statically detect memory ordering misuses for Rust.

This work follows up Boqin Qin's Rust study in [Understanding and Detecting Real-World Safety Issues](https://github.com/BurtonQin/lockbud) in TSE'24.
I focus on atomic concurrency bugs and performance loss due to memory ordering misuse in this paper.

Please refer to our paper for more memory ordering misuse categories in Rust.


## Install
Currently supports rustc nightly-2023-03-09
```sh
$ git clone https://github.com/AtomVChecker/AtomVChecker.git
$ cd section-5-detection/AtomVChecker
$ rustup component add rust-src
$ rustup component add rustc-dev
$ rustup component add llvm-tools-preview
$ cargo install --path .
```

Note that you must use the same rustc nightly version as AtomVChecker to detect your project!
You can either override your rustc version or specify rust-toolchains in your project.

## Example
Test RUSTSEC_2022_0006 and RUSTSEC_2022_0029
```sh
# Execute from the section-5-detection/AtomVChecker
$ ./detect.sh examples/RUSTSEC_2022_0006
```
It will print one atomic concurrency bug(ARC bug) in json format, like the following one:

```
    [
      {
        "AtomicCorrelationViolation": {
          "bug_kind": "AtimicCorrelationViolation",
          "possibility": "Possibly",
          "diagnosis": {
            "atomic": "src/main.rs:381:33: 381:56"
          },
          "explanation": "Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using Acquire is sufficient to ensure the program's correctness."
        }
      }
    ]
```

```sh
# Execute from the section-5-detection/AtomVChecker
$ ./detect.sh toys/RUSTSEC_2022_0029
```
It will print one atomic concurrency bug(CIU bug):

```
      {
        "AtomicCorrelationViolation": {
          "bug_kind": "AtimicCorrelationViolation",
          "possibility": "Possibly",
          "diagnosis": {
            "atomic": "src/main.rs:298:41: 298:54"
          },
          "explanation": "Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using Acquire is sufficient to ensure the program's correctness."
        }
      },
      {
        "AtomicCorrelationViolation": {
          "bug_kind": "AtimicCorrelationViolation",
          "possibility": "Possibly",
          "diagnosis": {
            "atomic": "src/main.rs:177:45: 177:65"
          },
          "explanation": "Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using Release is sufficient to ensure the program's correctness."
        }
      }
```

If you want to check for atomic correlations, you can set the `ATOMVCHECKER_LOG` in detexct.sh to debug (default is info), which will output all atomic operations and the corresponding minimum memory ordering requirements

```sh
# debug mode(check for atomic correlations)
$ export ATOMVCHECKER_LOG=debug
```

The atomic correlation outputs for RUSTSEC-2022-0029 is as follows:
```
    {
      AtomicInfo { 
        atomic_place: Some(_56), 
        atomic_value: [_55], 
        atomic_operate: Some(Load), 
        caller_instance: NodeIndex(55), 
        ordering: [Relaxed], 
        source_info: "src/main.rs:298:41: 298:54" 
        }: {Acquire}, 
      AtomicInfo { 
        atomic_place: Some(_66), 
        atomic_value: [], 
        atomic_operate: Some(Store), 
        caller_instance: NodeIndex(65), 
        ordering: [Relaxed], 
        source_info: "src/main.rs:177:45: 177:65" 
        }: {Release}
    }: 2
```


`detect.sh` is mainly for development of the detector and brings more flexibility.
You can modify `detect.sh` to use release vesion of AtomVChecker to detect large and complex projects.

For ease of use, you can also run cargo atomvchecker
```sh
$ cd section-5-detection/AtomVChecker/examples/RUSTSEC_2022_0006; cargo clean; cargo atomvchecker -k atomicity_violation
```
Note that you need to run
```sh
cargo clean
```
before re-running atomvchecker.

You can also specify blacklist or whitelist of crate names.

The `-b` implies the list is a blacklist.

The `-l` is followed by a list of crate names seperated by commas.

The `-k` implies the type of detection, currently only supporting `atomicity_violation`.
```sh
$ cd YourProject; cargo clean; cargo atomvchecker -k atomicity_violation -b -l cc,tokio_util,indicatif
```

## Credits
We owe a great deal of our ideas and code to the following projects, and we would like to express our deepest gratitude to them!

* [MIRAI](https://github.com/facebookexperimental/MIRAI)
* [lockbud](https://github.com/BurtonQin/lockbud)

