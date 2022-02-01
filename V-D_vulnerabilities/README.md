# V-D Vulnerabilities

This directory contains the crashing input files and scripts to reproduce crashes found during fuzzing, as described in the paper.

## Requirements

The scripts are known to work with the release version of FirmWire v1.1.0 ([link](https://github.com/FirmWire/FirmWire/tree/v1.1.0)) on an Ubuntu 20.04 system. As fuzzer, we used AFL++ v3.13a (git commit [#f66a4de](https://github.com/AFLplusplus/AFLplusplus/tree/f66a4de18a013eeb1aed27a9e38e8209ce168c1c)), but any more recent version should do.

As these experiments require task injection, the toolchains & compiler to build mods are required. For Ubuntu 20.04, these can be obtained by installing the `gcc-9-mipsel-linux` and `gcc-arm-none-eabi` packages.

In question of doubt, use the [firmwire Docker](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile) image.

## Setup

1) Specify the path of your local FirmWire and experiments repositories:
    ```
    export EXPERIMENT_ROOT=path/to/your/ndss22_experiments-repository
    export FIRMWIRE_ROOT=/path/to/your/firmwire-repository
    ```
2) Make sure to have the fuzzing mods built (can be skipped if working with the FirmWire Docker):
    ```
    cd $FIRMWIRE_ROOT/mods && make
    ```

    NOTE: for RRC#4 (MTK), you will need to change the `FirmWire/modkit/mtk/fuzzers/lte_rrc.c` file to enable the crash. Currently the crash is shallow so the fuzzer NOPs out parts of the code to skip past to find deeper crashes. You will need to comment out the following memcpy:

    ```
    // disable the AsnFreeDecodedWithBlock call in errc_asn1_mem_free
    // we don't care about the double-free on the error path (for MCCH)
    //memcpy(errc_asn1_mem_free, jrcnop, 4);
    // ^^^^^^^^^^^ comment the memcpy
    ```

3) Run the `./repro.py BUG` script with a bug name as an argument. The bugs accepted are: CC1,CC2,RRC1,RRC2,RRC3,RRC4,SM

## Crash Mapping

The included crash files in `crashes/` map to crash names in the paper like so:

* `GSM_CC_Bearer_Crash_MEM_GUARD_G973F_ASG8.bin` - CC#1
* `GSM_CC_SETUP_MSG_ProAsn_PREFETCH_ABORT_G973F_CTD1.bin` - CC#2
* `GSM_SM_PREFETCH_ABORT_G950_AQI7.bin` - SM
* `LTE_RRC_LRRCConnectionReconfiguration_v890_IEs_PREFETCH_ABORT_G973F_CTD1.bin` - RRC#1
* `LTE_RRC_ProAsn_Encode_MEM_GUARD_G973F_9FUCD.bin` - RRC#2
* `LTE_RRC_RRCConnectionReconfiguration_SIB2_PREFETCH_ABORT_G973F_9FUCD.bin` - RRC#3
* `LTE_RRC_MTK_MCCH_DoubleFree_A41_ATE1.bin` - RRC#4
