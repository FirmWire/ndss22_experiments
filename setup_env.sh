if [[ ! -f "./firmwire.py" ]]; then
    echo "Couldn't find firmwire.py. Please source this script from your firmwire directory!"
    exit -1
fi

if [[ $0 == $BASH_SOURCE ]]; then
    echo "It seems you tried to run this script. Please use `source ndss22_experiments/setup_env.sh` instead!"
    exit -2
fi

export FIRMWIRE_ROOT="$PWD"
export EXPERIMENT_ROOT=`dirname $(realpath "$BASH_SOURCE")`

# Check if we are running inside a (firmwire) docker container
if [[ ! $IS_DOCKER ]]; then
    # Comment this if you have FirmWire installed on your host machine
    # Otherwise install it using the Dockerfile installation provided at https://firmwire.github.io/docs/installation.html
    export USE_DOCKER=1
else
    # Don't use docker if we are already inside a container
    export USE_DOCKER=0
fi

echo "All set! You can now run the FirmWire experiments from this terminal."

