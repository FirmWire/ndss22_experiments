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

DIR="$(dirname "$(readlink -f "$0")")"
RESULT_DIR="${DIR}/results/shannon/"
CRASH_DIR="${EXPERIMENT_ROOT}/V-D_vulnerabilities/crashes"
IMAGE_FOLDER="$(readlink -f ${1})"
SNAP_FILE="$(readlink -f ${2})"

mkdir -p "${RESULT_DIR}"
 
cd "${FIRMWIRE_ROOT}"

while read content; do
  name_addr=($content)
  image="${name_addr[0]}"
  # do we have commented lines?
  if [[ ${image:0:1} == "#" ]]; then
      continue
  fi

  for c in $(ls "${CRASH_DIR}" | grep -v MTK);  do
      fuzztask=$(echo ${c} | cut -d '_' -f1-2 |  awk '{print tolower($0)}')
      timeout 200 python3 -u ./firmwire.py \
          --fuzz-triage "${fuzztask}" \
          --fuzz-input "${CRASH_DIR}/${c}" \
          --restore-snapshot $image \
          $IMAGE_FOLDER/$image 2>&1
      if [[ $? -eq 124 ]] ; then
          echo "TIMEOUT"
      fi
      echo ${c}
      echo -e "====================================================\n\n\n"
  done | tee ${RESULT_DIR}/$image.log

done < $SNAP_FILE

