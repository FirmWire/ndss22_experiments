# FirmWire: NDSS'22 Experimental Data

This repository holds the experiments as reported in our [paper (PDF)](https://www.ndss-symposium.org/wp-content/uploads/2022-136-paper.pdf).
Each subdirectory directly maps to one of the subsections in the paper and provides independent README.md files on how to run the experiments.

The experiments were tested with the official FirmWire docker (which is based on Ubuntu 20.04) for [FirmWire v1.1.0](https://github.com/FirmWire/FirmWire/tree/v1.1.0) and Ghidra 10.04. See the [installation instructions](https://firmwire.github.io/docs/installation.html) before continuing.

Some of our experiments need knowledge of the location of the firmwire and `ndss22_experiments` directories on your local disk.
To ease this process, we provide a [`setup_env.sh`](setup_env.sh) bash script - when sourced from your *FirmWire* repository, you should be all set!

```
$ cd /path/to/firmwire/directory/
$ source /path/to/ndss22_experiments/directory/setup_env.sh
```

Then `cd` to the experiment folder you want to run.

## Directory Information

### [firmware_samples](firmware_samples)
Contains the firmware samples used during the evaluation (Section 5/V in the paper). Different evaluation sections have their own README.
For all of the firmware used in our work, see [the Zenodo repository containing them.](https://doi.org/10.5281/zenodo.6516029)

### [V-A_fuzzing_campaigns](V-A_fuzzing_campaigns)
This directory contains the required scripts to replicate the fuzzing campaigns described in the paper.

### [V-B_fuzzing_performance](V-B_fuzzing_performance)
This contains the scripts used to build the coverage graphs and table.

### [V-C_basesafe_comparison](V-C_basesafe_comparison)
The code developed to compare against BaseSAFE.

### [V-D_vulnerabilities](V-D_vulnerabilities)
This directory contains the crashing input files and scripts to reproduce crashes found during fuzzing, as described in the paper.

### [V-E_extending_firmwire](V-E_extending_firmwire)
Contains the `diff` from the pre-release FirmWire codebase showing the lines of code added/removed/changed for supporting the Samsung Galaxy S7/S7edge (SM-G930F) firmware (Shannon 335AP).

### [V-F_large_scale_analysis](V-F_large_scale_analysis)
Contains the scripts to perform the large scale vulnerability analysis of baseband firmware.

### [V-G_ota_reproduction](V-G_ota_reproduction)
The subdirectories of this folder contain the patches for replaying our found crashes over the air. 

