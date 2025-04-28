#!/bin/bash
cargo rustc --profile=check -- -Zunpretty=expanded | \
  sed -e s/secret_structs::secret/cocoon/ \
      -e s/check_ISEF_mut_ref/check_ISEF/ \
      -e s/check_ISEF_unsafe/check_ISEF_unsafe/ \
      -e s/unwrap_consume_unsafe/unwrap/ \
      -e s/unwrap_unsafe/unwrap_ref/ \
      -e s/unwrap_mut_unsafe/unwrap_mut_ref/ \
      -e s/' std::'/' ::std::'/ \
      -e s/'(std::'/'(::std::'/ \
  > expanded.rs

