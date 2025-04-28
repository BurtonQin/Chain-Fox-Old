#!/bin/bash

# Copyright © 2016–2020 University of Malta

# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved. This file is offered as-is,
# without any warranty.

set -e
shopt -s globstar

SUFFIX=.original

if [ "$1" = restore ]; then
    for f in src/**/*.rs$SUFFIX; do
        mv "$f" "${f%$SUFFIX}"
    done
    exit
fi

EXTRACT_SCRIPT='
p                       # print original, as sed is called quiet
/```rust$/,/```$/{      # work between ```rust and ```
    \,//[/!],!s,^,        , # indent uncommented lines
    s, *//[/!],       ,     # uncomment commented lines
    s, *$,,                 # remove trailing spaces
    s,^\( *\)# ,\1/* # */ , # comment hiding hash
    s,    ```rust$,{,       # replace ```rust with {
    s, rug::, crate::,      # replace rug:: with crate::
    s,fn main(),/* & */,    # comment fn main()
    s,    ```,},            # replace ``` with }
    H                       # append to hold
}
${                      # at the end of the file
    x                       # move the hold to pattern space
    /./{                    # if hold was not empty
        s/^.//                  # remove leading newline
        i\
// AUTOEXTRACTED DOCTESTS BELOW
        i\
#[test]
        i\
fn check_doctests() {
        p                       # print the hold (wrapped by fn)
        i\
    #[cfg(feature = "float")]
        i\
    {
        i\
        use crate::float::{self, FreeCache};
        i\
        float::free_cache(FreeCache::All);
        i\
    }
        i\
}
    }
}'
sed -i$SUFFIX -n -e "$EXTRACT_SCRIPT" src/**/*.rs
