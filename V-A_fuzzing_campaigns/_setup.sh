_run_docker_base() {
  docker run --rm \
    --user $(id -u):$(id -g) \
    -v ${EXPERIMENT_ROOT}:${EXPERIMENT_DOCKER_ROOT} \
    -v ${FIRMWIRE_ROOT}:${FIRMWIRE_DOCKER_ROOT} \
    -w ${FIRMWIRE_DOCKER_ROOT} \
    $@
}

_run_docker() {
    _run_docker_base firmwire $@
}

run_wrapper() {
  if  [[ "${USE_DOCKER}" = 1 ]]; then
    _run_docker $@
  else
    $@
  fi
}

run_afl() {

  if  [[ "${USE_DOCKER}" = 1 ]]; then
    _run_docker_base \
      -e AFL_NO_UI=1 \
      -e AFL_FORKSRV_INIT_TMOUT=300000 \
      -e AFL_DEBUG_CHILD=1 \
      -e AFL_DEBUG_CHILD_OUTPUT=1 \
      firmwire \
      timeout 86400 \
      ${EXPERIMENT_AFL_BIN} \
      $@
  else
    export AFL_NO_UI=1
    export AFL_FORKSRV_INIT_TMOUT=300000

    # Default 24hr timeout
    timeout 86400 \
    ${EXPERIMENT_AFL_BIN} \
    $@
  fi
}

run_firmwire() {
  run_wrapper "${FIRMWIRE_BIN}" $@
}

if [[ -z "${FIRMWIRE_ROOT}" ]]; then
  echo "FIRMWIRE_ROOT environment variable not set. Please specify the directory of your FirmWire repository!"
  exit -1
fi

if [[ -z "${EXPERIMENT_ROOT}" ]]; then
  echo "EXPERIMENT_ROOT environment variable not set. Please specify the directory of your ndss22-experiments repository!"
  exit -1
fi

export FIRMWIRE_BIN="${FIRMWIRE_ROOT}/firmwire.py"
export EXPERIMENT_AFL_DIR="${EXPERIMENT_ROOT}/AFLplusplus"
export EXPERIMENT_AFL_BIN="${EXPERIMENT_AFL_DIR}/afl-fuzz"

if [ ! -x "${FIRMWIRE_BIN}" ]; then
  echo "Missing firmwire.py in ${FIRMWIRE_ROOT}"
  exit 1
fi

if [ ! -x "${EXPERIMENT_AFL_BIN}" ]; then
  echo "Missing afl-fuzz in ${EXPERIMENT_AFL_DIR}"
  exit 1
fi

echo "USE_DOCKER: ${USE_DOCKER}"
echo "FIRMWIRE_BIN: ${FIRMWIRE_BIN}"
echo "EXPERIMENT_AFL_BIN: ${EXPERIMENT_AFL_BIN}"

if  [[ "${USE_DOCKER}" = 1 ]]; then
  if [[ -z $(which docker) ]]; then
    echo "Error: unable to find docker binary. Install docker or use FirmWire on the host system (USE_DOCKER=0)."
    exit 1
  fi
  export FIRMWIRE_DOCKER_ROOT="${FIRMWIRE_ROOT}"
  export EXPERIMENT_DOCKER_ROOT="${EXPERIMENT_ROOT}"
fi

run_firmwire -h > /dev/null
if [[ $? != 0 ]]; then
  echo "Failed to run firmwire binary"
  exit 1
else
  echo "FirmWire binary working"
fi

echo "Building modules..."
run_wrapper make -C "${FIRMWIRE_ROOT}/modkit"

if [[ $? != 0 ]]; then
  echo "Failed to build modules"
  exit 1
fi

run_afl -h > /dev/null
if ! [ $? -le 1 ]; then
  echo "Failed to run AFL"
  exit 1
else
  echo "AFL binary working"
fi
