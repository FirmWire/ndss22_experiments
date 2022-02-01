#!/bin/bash

source _setup.sh

cd $FIRMWIRE_ROOT
while read content; do
  name_addr=($content)
  image="${name_addr[0]}"
  addr="${name_addr[1]}"
  if [[ ${image:0:1} == "#" ]]; then
      continue
  fi
  run_firmwire \
   --fuzz-triage lte_rrc \
   --fuzz-input "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/inputs/blank/AAAA" \
   --snapshot-at $addr,$image \
   "$EXPERIMENT_ROOT/firmware_samples/$image"
done < "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/fuzzing_snapshots.txt"

