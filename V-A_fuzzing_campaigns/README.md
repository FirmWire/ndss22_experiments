# V-A Fuzz Testing

This directory contains the required scripts to replicate the fuzzing campaigns described in the paper.

## Requirements

The scripts are known to work with the release version of FirmWire (git commit 6de26f8dfb) on an Ubuntu 20.04 system. As fuzzer, we used AFL++ v3.13a (git commit [#f66a4de](https://github.com/AFLplusplus/AFLplusplus/tree/f66a4de18a013eeb1aed27a9e38e8209ce168c1c)), but any more recent version should do.

As these experiments require task injection, the toolchains & compiler to build mods are required. For Ubuntu 20.04, these can be obtained by installing the `gcc-9-mipsel-linux` and `gcc-arm-none-eabi` packages.

In question of doubt, use the [firmwire Docker](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile) image.

## Setup

1) Activate the `setup_env.sh` script as mentioned in the top-level README

2) Make sure to have the fuzzing modules built (if not using Docker):
    ```
    cd $FIRMWIRE_ROOT/modkit && make
    ```

3) Clone and build AFL++:
    ```
    cd $EXPERIMENT_ROOT
    git clone https://github.com/AFLplusplus/AFLplusplus.git
    cd AFLplusplus
    # Checkout the version used for evaluation
    git checkout f66a4de18a013eeb1aed27a9e38e8209ce168c1c 
    make
    ```

4) Create the fuzzing snapshots:
    ```
    cd $EXPERIMENT_ROOT/V-A_fuzzing_campaigns
    ./create_fuzzing_snapshots.sh
    ```

    Each snapshot should end with output similar to:
    ```
    [INFO] firmwire.emulator.snapshot: Taking snapshot CP_G973FXXU1ASBA_CP12016348_CL15445945_QB22242603_REV01_user_low_ship.tar.md5 to /ndss22_experiments/firmware_samples/CP_G973FXXU1ASBA_CP12016348_CL15445945_QB22242603_REV01_user_low_ship.tar.md5_workspace/snapshots.qcow2 (reason: Snapshot at command line)
    [INFO] firmwire.emulator.snapshot: Saving snapshot auxiliary data to /ndss22_experiments/firmware_samples/CP_G973FXXU1ASBA_CP12016348_CL15445945_QB22242603_REV01_user_low_ship.tar.md5_workspace/CP_G973FXXU1ASBA_CP12016348_CL15445945_QB22242603_REV01_user_low_ship.tar.md5.snapinfo
    [INFO] firmwire.emulator.snapshot: Snapshotting QEMU state...
    [INFO] firmwire.emulator.snapshot: Snapshot completed!
    ```

    You should see `_workspace` directories in the `firmware_samples/` directory.
    NOTE that only shannon baseband image snapshots are created.

5) Run afl-system-config to provide optimal OS settings for fuzzing:
    ```
    cd $EXPERIMENT_ROOT/AFLplusplus
    sudo ./afl-system-config
    ```

6) Start the fuzzing campaings! For MediaTek images, just run the fuzz script:
    ```
    cd $EXPERIMENT_ROOT/V-A_fuzzing_campaigns
    ./fuzz_mtk.sh
    ```

    For shannon images, we provide different fuzzer, which can be selected via the command-line argument to the `fuzz_shannon.sh` script. For instance, to fuzz the gsm_cc protocol, run the following:
    ```
    cd $EXPERIMENT_ROOT/V-A-fuzzing_campaigns
    ./fuzz_shannon.sh gsm_cc
    ```

    Each script will spawn 5 instances of the choosen fuzzer for each of the applicable firmware images, running 24 hours each. Note that the output directories are seperated to avoid testcase sharing between different AFL instances. If you want to run the campaings in a different way, please adjust the corresponding `fuzz_{vendor}.sh` scripts.

## FAQ

#### Q: Why do I need to create snapshots?

Strictly speaking, snapshots are not required, and fuzzing can be done by starting emulation from boot and using the `AFL_FORKSRV_INIT_TMOUT` environment variable to advise AFL++ that the forkserver will take a while to spin up. However, we used snapshots during our fuzzing experiments in the paper, and we want to mirror our experiments as closely as possible in this repository.

#### Q: Why do we only use snapshots for shannon images, and not for the MTK ones?

Good question! When we started MTK fuzzing, the snapshot feature was not supported yet for the MTK vendor plugin, so we fuzzed without snapshots. Once again, we aim to provide a setup as close as possible to the one used in the evaluation in the paper.

#### Q: Where do the snapshot addresses come from?

We used a coarse grained heuristing based on the modem debug log messages to identify when the boot process is finished. For more information, and automated scripts to obtain these addresses, check the [V-F_large_scale_analysis](../V-F_large_scale_analysis) directory.

#### Q: I'm starting the fuzz scripts, but nothing seems to be happening.

It may be that AFL++ couldn't start correctly. One reason, for instance, could be that you are running the experiments inside the docker container leading to `afl-system-config` not being able to set up the operating system properly. As workaround, try to execute afl-system-config from your host, rather from the docker container.

#### Q: What are those seeds in the GSM_CC directory

The seeds we used for our 24h gsm_cc fuzzing campaign come from a prior gsm_cc fuzzing session, which used the input contained in the `./inputs/blank` directory.

