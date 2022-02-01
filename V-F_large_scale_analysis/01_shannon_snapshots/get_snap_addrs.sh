#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -lt 1 ]; then
    echo "Usage: $0 IMAGE_FOLDER"
    echo -e "\t This scripts requires the folder with the images to analyze as argument!"
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
cd "$FIRMWIRE_ROOT"

export PYTHONUNBUFFERED=1 # Force unbuffered output to catch the right output
for modem_img in $(ls "$IMAGE_FOLDER" | grep CP_G | grep -v workspace); do
    echo -n "$(basename "$modem_img") ";
    timeout 500 \
    ./firmwire.py  \
        --fuzz-triage lte_rrc \
        --fuzz-input "$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/inputs/blank/AAAA" \
        "${IMAGE_FOLDER}/${modem_img}" 2>&1 | \
     grep -a '\[BTL\]' | tail -n1 | sed -r 's/.*(0x[0-9a-f]{8}).*\.*/\1/'
     echo # Additional echo in case snapp_addr wasn't found
done | tee "$DIR/snap_addrs.txt"

# Remove empty lines introduced by the additional echo
sed -i '/^$/d' "$DIR/snap_addrs.txt"

# Comment non successful images:
sed -E -i "s/^(.*.md5) $/#\1/g" "$DIR/snap_addrs.txt"
