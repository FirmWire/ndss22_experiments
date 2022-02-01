#!/bin/bash

VALID_FUZZERS=("lte_rrc" "gsm_cc" "gsm_sm")

source _setup.sh

case "$1" in
  gsm_cc|gsm_sm|lte_rrc)
    fuzz_target="$1"
    echo "Fuzzing $fuzz_target"
    ;;
  *)
    echo "Please specify fuzzer as first argument! (Valid options: gsm_cc, gsm_sm, lte_rrc)"
    exit -1
    ;;
esac

n_modem=0
cd $FIRMWIRE_ROOT
while read content; do
  name_addr=($content)
  image="${name_addr[0]}"
  # do we have commented lines?
  if [[ ${image:0:1} == "#" ]]; then
      continue
  fi

  mkdir -p "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results/$image"

  for i in {1..5}; do
      echo "Starting fuzzer $i for image $image"
      run_out="$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results/$image/${fuzz_target}_run_${i}"
      mkdir -p "${run_out}"

      run_afl \
          -i "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/inputs/$fuzz_target" \
          -o "${run_out}" \
          -t 10000 \
          -m none \
          -M "main" \
          -U -- ./firmwire.py \
            --fuzz $fuzz_target \
            --fuzz-input @@  \
            --consecutive-ports 3${n_modem}${i}00 \
            --restore-snapshot $image \
            "$EXPERIMENT_ROOT/firmware_samples/$image" > "${run_out}/afl.log" &
      sleep 5
  done
  let n_modem+=1

done < $EXPERIMENT_ROOT/V-A_fuzzing_campaigns/fuzzing_snapshots.txt

