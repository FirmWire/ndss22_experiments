#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 IMAGE_FOLDER SNAP_ADDR_FILE"
    echo -e "\t This scripts requires the folder with the images to analyze and a snap address file as argument!"
    exit -1
fi

if [[ -z "${FIRMWIRE_ROOT}" ]]; then                                                                                                                                           
  echo "FIRMWIRE_ROOT environment variable not set. Please specify the directory of your FirmWire repository!"
  exit -1
fi

if [[ -z "${EXPERIMENT_ROOT}" ]]; then
  echo "EXPERIMENT_ROOT environment variable not set. Please specify the directory of your ndss22-experiments repository!"
  exit -1
fi

IMAGE_FOLDER="$(readlink -f ${1})"
SNAP_FILE="$(readlink -f ${2})"

cd "$FIRMWIRE_ROOT"

while read content; do
  name_addr=($content)
  image="${name_addr[0]}"
  addr="${name_addr[1]}"

  if [[ ${image:0:1} == "#" ]]; then
      continue
  fi

  echo "[+] Creating Snapshot for ${image} at ${addr}"
  timeout 600 \
    python3 -u firmwire.py \
    --fuzz-triage lte_rrc \
    --fuzz-input $EXPERIMENT_ROOT/V-A_fuzzing_campaigns/inputs/blank/AAAA \
    --snapshot-at $addr,$image $IMAGE_FOLDER/$image > /tmp/last_snap_run.txt 2>&1 
done < $SNAP_FILE 