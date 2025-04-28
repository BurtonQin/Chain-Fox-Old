# Servo
Servo's source code is located [here](https://github.com/obicons/servo-ifc).
It is out-of-tree because it contains this repository as a submodule, and
because it is a large project.

## Results
Raw results are in the `results` subdirectory included here.

## Docker
Experiments were conducted using this Docker version:
```
$ docker --version
Docker version 24.0.5
```

But newer versions __should__ also work.

## Reproducing
Run these commands:
```bash
# clone the servo-ifc repository into a location outside of the Cocoon root directory
$ git clone git@github.com:obicons/servo-ifc.git
$ cd servo-ifc
$ cp -R [Cocoon artifact's root directory path] ./info-flow-library
# This command will take ~60 minutes.
$ docker image build -t servo-ifc ./
$ mkdir results && chmod -R a+rwx results
$ docker container run -ti -v $(pwd)/results:/home/servo/results servo-ifc bash
$ ./evaluate-internal.sh
```

We suggest evaluating in a tmux environment since this experiment takes
several hours to complete.
