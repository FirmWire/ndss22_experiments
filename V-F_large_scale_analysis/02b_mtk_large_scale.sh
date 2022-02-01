#!/bin/bash

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

DIR="$(dirname "$(readlink -f "$0")")"
RESULT_DIR="${DIR}/results/mtk/"
CRASH_DIR="${EXPERIMENT_ROOT}/V-D_vulnerabilities/crashes"
IMAGE_FOLDER="$(readlink -f ${1})"

mkdir -p "${RESULT_DIR}"

cd "${FIRMWIRE_ROOT}"

echo "[+] Preparing lte rrc fuzzer to allow crashes"
sed -i 's#memcpy(errc_asn1_mem_free, jrcnop, 4);#//memcpy(errc_asn1_mem_free, jrcnop, 4);#g' "$FIRMWIRE_ROOT/modkit/mtk/fuzzers/lte_rrc.c"
cd $FIRMWIRE_ROOT/modkit && make clean && make

cd "${FIRMWIRE_ROOT}"

for image in $(ls ${IMAGE_FOLDER} | grep CP_A | grep -v workspace); do
    empty_dir="/tmp/empty_nv"
    empty_dir_lower="/tmp/empty_nv/vendor/nvdata"
    mkdir -p "${empty_dir}" "${empty_dir_lower}"

  for c in $(ls "${CRASH_DIR}" | grep MTK);  do
      fuzztask=$(echo ${c} | cut -d '_' -f1-2 |  awk '{print tolower($0)}')
      timeout 200 python3 -u ./firmwire.py \
          --fuzz-triage "${fuzztask}" \
          --fuzz-input "${CRASH_DIR}/${c}" \
          --mtk-loader-nv_data "${empty_dir}" \
          $IMAGE_FOLDER/$image 2>&1
      if [[ $? -eq 124 ]] ; then
          echo "TIMEOUT"
      fi
      echo ${c}
      echo -e "====================================================\n\n\n"
  done | tee ${RESULT_DIR}/$image.log
  rm -r "${empty_dir}"

done

# Restore changes
sed -i 's#//memcpy(errc_asn1_mem_free, jrcnop, 4);#memcpy(errc_asn1_mem_free, jrcnop, 4);#g' "$FIRMWIRE_ROOT/modkit/mtk/fuzzers/lte_rrc.c"
