#!/bin/bash

# This script runs multiple, interleaved trials of spotify-tui-original and spotify-tui
# and collects run times.
# We modified both to measure run times of the execution
# related to the client secret.
# They append run times to modified_results.txt, which this script collects
# in differently named files in ifc_examples/.

set -e

TRIALS=1000
if [ -n "$1" ]
then
  TRIALS=$1
fi

for dir in spotify-tui-original spotify-tui-cocoon
do
  pushd $dir/src > /dev/null
  cargo build --release >/dev/null 2>/dev/null
  rm -f $dir/src/modified_results.txt
  rm -f $dir-results.csv
  popd > /dev/null
done

echo Running $TRIALS trials...

echo "elapsed (ns)" >> spotify-tui-original-results.csv
echo "elapsed (ns)" >> spotify-tui-cocoon-results.csv

x=1
while [ $x -le $TRIALS ]
do
  for dir in spotify-tui-original spotify-tui-cocoon
  do
    pushd $dir/src > /dev/null
    rm -f ~/.config/spotify-tui/client.yml
    ../../../../target/release/spt < input.txt
    popd > /dev/null
  done
  x=$(( $x + 1 ))
done

for dir in spotify-tui-original spotify-tui-cocoon
do
  mv $dir/src/modified_results.txt $dir-results.csv
  python3 ../benchmark_games/data/analyze.py $dir-results.csv
done

echo Finished $TRIALS trials
