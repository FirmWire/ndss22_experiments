#!/bin/bash

source _setup.sh

IMAGES=(
"CP_A415FXXU1ATE1_CP15883562_CL18317596_QB31188168_REV00_user_low_ship_MULTI_CERT.tar.md5"
"CP_A415FXXU1BUA1_CP17952712_CL20194519_QB37484013_REV00_user_low_ship_MULTI_CERT.tar.md5"
)


n_modem=0
cd $FIRMWIRE_ROOT
for image in ${IMAGES[@]}; do
  mkdir -p "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results/$image"

  # Only single instance supported
  for i in {1..5}; do
      echo "Starting fuzzer $i for image $image"
      run_out="$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results/$image/lte_rrc_run_$i"
      mkdir -p "${run_out}"

      # MTK images need a blank NVdata folder to continue
      empty_dir="${run_out}/empty_nv"
      empty_dir_lower="${run_out}/empty_nv/vendor/nvdata"
      mkdir -p "${empty_dir}" "${empty_dir_lower}"

      run_afl \
          -i "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/inputs/lte_rrc" \
          -o "${run_out}" \
          -t 10000 \
          -m none \
          -M "main" \
          -U -- ./firmwire.py \
            --workspace SCRATCH \
            --fuzz lte_rrc \
            --fuzz-input @@  \
            --consecutive-ports 4${n_modem}${i}00 \
            --mtk-loader-nv_data "${empty_dir}" \
            --fuzz-persistent 1000 \
            "$EXPERIMENT_ROOT/firmware_samples/$image" > "${run_out}/afl.log" &
      sleep 30
  done
  let n_modem+=1
done


