#!/bin/bash

# Copyright © 2016–2020 University of Malta

# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved. This file is offered as-is,
# without any warranty.

set -e
shopt -s globstar

# This filter script is for tarpaulin 0.14.3:

FILTER_SCRIPT='
# modify uncovered lines list
/Uncovered Lines/,/Tested\/Total Lines:/{
    # make lines friendly with emacs compilation mode
    s/^|| //
    s/^\(.*\): \(..*\)/\1:\2: Uncovered/
    # if the line contains a comma split it, repeating prefix and suffix
    s/\(^\)\(.*\):\([^,]*\), \(.*: Uncovered\)$/\1\2:\3: Uncovered\n\2:\4/
: repeat
    # like above, but work on last line only
    s/\(.*\n\)\(.*\):\([^,]*\), \(.*: Uncovered\)$/\1\2:\3: Uncovered\n\2:\4/
    # if a line was split, repeat
    t repeat
}
p                       # print the line(s) as sed is invoked with -e
'

EXCLUDE="--exclude-files build.rs src/ext/xmpz32.rs"
cargo tarpaulin -v --features serde --ignore-tests $EXCLUDE |& sed -n -e "$FILTER_SCRIPT"
