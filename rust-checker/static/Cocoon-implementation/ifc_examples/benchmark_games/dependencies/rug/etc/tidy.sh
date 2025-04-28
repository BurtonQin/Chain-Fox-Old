#!/bin/bash

# Copyright © 2016–2020 University of Malta

# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved. This file is offered as-is,
# without any warranty.

error_code=0

function print_eval_check {
    printf '$'
    for word in "$@"; do
        if [[ "$word" != *\ * ]]; then
            printf ' %q' "$word"
        elif [[ "$word" =~ ^[\ /0-9A-Z_a-z-]*$ ]]; then
            printf ' "%s"' "$word"
        else
            printf ' %q' "$word"
        fi
    done
    printf '\n'
    eval $(printf '%q ' "$@")
    code=$?
    if [ $code == 0 ]; then
        return
    fi
    printf '\n*** Command exited abnormally with code %s\n' "$code"
    error_code=$code
}

# prepend "+" if TOOLCHAIN is set
TOOLCHAIN=${TOOLCHAIN:++$TOOLCHAIN}

# Check formatting.
print_eval_check \
    cargo $TOOLCHAIN \
    fmt -- --check

# Check clippy with all feature combinations.
# integer,rational = rational
# integer,rand = rand
# float,complex = complex
for features in \
    '' gmp-mpfr-sys{,\ gmp-mpfr-sys/{mpfr,mpc}} \
    integer{,\ float,\ complex}{,\ serde} \
    rational{,\ float,\ complex}{,\ rand}{,\ serde} \
    float{,\ rand}{,\ serde} \
    complex{,\ rand}{,\ serde} \
    rand{,\ serde} \
    serde
do
    if [[ "$features" =~ ^(()|serde)$ ]]; then
        gmp=""
    else
        gmp="-p gmp-mpfr-sys"
    fi
    features="fail-on-warnings${features:+ $features}"
    print_eval_check \
        cargo $TOOLCHAIN clippy --all-targets \
        --no-default-features --features "$features" \
        $gmp -p rug
done

if [ $error_code != 0 ]; then
    exit $error_code
fi
