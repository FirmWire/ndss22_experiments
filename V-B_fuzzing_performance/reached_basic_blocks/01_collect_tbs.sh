#!/bin/bash


if [[ -z "${FIRMWIRE_ROOT}" ]]; then
  echo "FIRMWIRE_ROOT environment variable not set. Please specify the directory of your FirmWire repository!"
  exit -1
fi

if [[ -z "${EXPERIMENT_ROOT}" ]]; then
  echo "EXPERIMENT_ROOT environment variable not set. Please specify the directory of your ndss22-experiments repository!"
  exit -1
fi

OUTPUT_DIR="${EXPERIMENT_ROOT}/V-B_fuzzing_performance/data/01_tb_collection"
mkdir -p "${OUTPUT_DIR}"

cd $FIRMWIRE_ROOT
dirs="$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results"
for fw_sample in $(ls $dirs); do
  image=$(basename $fw_sample)
  echo "[+] processing results for $image"

  if [[ $image = CP_A* ]]; then 
    for run in $(ls "$dirs/$image/" | grep "_run_"); do
        empty_dir="$dirs/$image/$run/empty_nv"
        fuzzer=$(echo $run | sed  s/_run.*//g)
        echo "[+] Collecting results for $image - $run"
        AFL_FORKSRV_INIT_TMOUT=1000000000 AFL_PRINT_FILENAMES=1 AFL_DEBUG_CHILD=1 \
            "$EXPERIMENT_ROOT/AFLplusplus/afl-showmap" \
            -i "$dirs/$image/$run/main/queue/" \
            -o "$dirs/$image/$run/main/showmap_out"  \
            -t 1000 \
            -U python3 -u ./firmwire.py \
            --trace-bb-translation \
            --fuzz $fuzzer \
            --fuzz-input @@ \
            --mtk-loader-nv_data "${empty_dir}" \
            "$EXPERIMENT_ROOT/firmware_samples/$image" 2>&1 > "${OUTPUT_DIR}/${image}_${run}.log"
    done 
  
  elif [[ $image = CP_G* ]]; then 
    for run in $(ls "$dirs/$image/" | grep "_run_"); do
        fuzzer=$(echo $run | sed  s/_run.*//g)
        echo "[+] Collecting results for $image - $run"
        AFL_FORKSRV_INIT_TMOUT=1000000000 AFL_PRINT_FILENAMES=1 AFL_DEBUG_CHILD=1 \
            "$EXPERIMENT_ROOT/AFLplusplus/afl-showmap" \
            -i "$dirs/$image/$run/main/queue/" \
            -o "$dirs/$image/$run/main/showmap_out"  \
            -t 1000 \
            -U python3 -u ./firmwire.py \
            --trace-bb-translation \
            --fuzz $fuzzer \
            --fuzz-input @@ \
            --restore-snapshot $image \
            "$EXPERIMENT_ROOT/firmware_samples/$image" 2>&1 > "${OUTPUT_DIR}/${image}_${run}.log"
    done 
  else
    echo "Unsupported image!"
  fi
done
