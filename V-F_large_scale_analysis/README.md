# Large-scale Vulnerability analysis

## 0) Firmware Collection

For insights on how we collected our data set, please check the scripts included in the [Firmware Collection](./firmware_collection/) subdirectory. In essence, there are two scripts: One for downloading firmware updates from https://www.sammobile.com/, and another one to unpack the modem firmware from the downloaded firmware updates.

As new firmware images are constantly released, and as sammobile may change their API at any point in time, we also mirrored downloaded and analyzed firmware images over at Zenodo. Click [the DOI](https://doi.org/10.5281/zenodo.6516029) to access our data set as used in the paper!
If you want to batch download all images contained in zenodo record, you can use the following one-liner:
```sh
for img in $(curl https://zenodo.org/record/6516030 | grep -P -o "https://zenodo.org/api/files/.*?CP_.*?.tar.md5"); do curl
 -O $img; done
```

## 1) Creating Snapshots (Shannon Only)

To speed up analysis, we created snapshots for the Shannon based modems. For doing so, please run `get_snap_addrs.sh` first. This will try to run all images in the specified folder with FirmWire, and checks for a magic string in the log output which gets printed only after bootup of the firmware image. This log output also contains the address from where the log function is called, which will be used as address for creating the snapshot. The result of `get_snap_addrs.sh` is a text file containing image names and addresses for where to take the snapshots.

Afterwards, the script `create_snaps.sh` takes this text file as input to rerun over all images, but this time actually taking the snapshots to be used later on.

For instance. if you downloaded the large scale data set into /home/FirmWire/images, you need to run the scripts as follows:
```
$ ./01_shannon_snapshots/get_snap_addrs.sh /home/FirmWire/images
$ ./01_shannon_snapshots/create_snaps.sh /home/FirmWire/images ./01_shannon_snapshots/snap_addrs.txt
```

At the time of writing, we did not have a working snapshot mechanism for MTK images. While added after the acceptance of the paper, we try to mirror the experiments here as close as possible.

## Run large scale analysis

This step will run all modem firmware with all different crashing inputs. There is one script for Shannon `03_shannon_large_scale.sh` and one for MTK `03_mtk_large_scale.sh` to carry out the experiments.
The result of these scripts are complete logs of the independent crash replay runs, stored into a individual .txt file per image in `${EXPERIMENT_ROOT}/V-F_large_scale_analysis/results/shannon/` and `${EXPERIMENT_ROOT}/V-F_large_scale_analysis/results/mtk/` directories.

The last logging messages of a single run will indicate whether a crash occurred or not, and if not, the scripts enhances the logging output with a `TIMEOUT` indication.

Like the scripts in the last step, the large scale scripts require the location of the large scale data set as argument, for instance:

```
$ ./02a_shannon_large_scale.sh /home/FirmWire/images
```
or
```
$ ./02b_mtk_large_scale.sh /home/FirmWire/images
```

Note that for MediaTek, the fuzzer code needs to be slightly different for different FirmWire versions. Adjusting the fuzzer code is *not* automated and needs to be done manually.
In particular, you need to ajdust the source code of the [LTE_RRC](https://github.com/FirmWire/FirmWire/tree/v1.1.0/modkit/mtk/fuzzers/lte_rrc.c) fuzzer to allow the large scale analysis for A10s images ([link](https://github.com/FirmWire/FirmWire/tree/v1.1.0/modkit/mtk/fuzzers/lte_rrc.c#L216)), and for A10 images before the `U5BTCB` build version ([link](https://github.com/FirmWire/FirmWire/tree/v1.1.0/modkit/mtk/fuzzers/lte_rrc.c#L219)).

## Parsing the logs

In the last step, the resulting log files are parsed and converted into a `csv` file, by using the `04_crashlog2csv.py` script. The dates for the firmware images is created by parsing the file names, as Samsung encodes the release date within the file name.

The script requires the large scale data set directory, the directory with the results from the last step, and the output file as argument, e.g.:
```
python3 04_crashlog2csv.py  /home/FirmWire/images/ ./results/shannon/ ./out.csv
```

We also provide the final csv for the experiment runs from our paper. Note that we conducted this step only for Shannon images, as for MTK images, we could identify crashes for all firmware images in the large scale data set.


