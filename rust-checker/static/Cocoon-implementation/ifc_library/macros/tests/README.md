# Testing
This directory contains a test-suite for the secret macros.

## Running tests
If you have a decent operating system (Linux, macOS), then you should run tests natively:
```sh
$ chmod +x tests/autotest.sh
$ tests/autotest.sh
```

Otherwise, you may run tests in a Docker container:
```sh
$ chmod +x tests/autotest_docker.sh
$ tests/autotest_docker.sh
```

## Writing tests
Each test must be self-contained in a `test_name.rs` file. They will be executed automatically by the `autotest.sh` script.

### Code that shouldn't compile
Code that shouldn't compile should go in a file named `no_compile_testname.rs`.

## Contributing
Please run the [shellcheck tool](https://www.shellcheck.net/) on `autotest.sh` if you change it. Bash is finicky, and shellcheck makes it more manageable. Also see ["Use Bash Strict Mode"](http://redsymbol.net/articles/unofficial-bash-strict-mode/).
