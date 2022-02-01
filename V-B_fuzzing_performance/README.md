# V-B Fuzzer Performance

The fuzzing performance evaluation is split in two parts: The general collection of [reached basic blocks](./reached_basic_blocks/), and the estimated [per-task coverage](./per_task_coverage).

We also provide parts of the [raw data](./data) we obtained from our fuzzing runs, to ease replication of the results shown in the paper.
If you are interested in all of the raw fuzzing data from our experiments, please reach out to us.

By default, all scripts assume that `EXPERIMENT_ROOT` and `FIRMWIRE_ROOT` environment variables are set correctly and that the results of the fuzzing runs are located in `$EXPERIMENT_ROOT/V-A_fuzzing_campaigns/results` which will be the case if the scripts from V-A were used.

## Generating reached basic blocks

### 1) Collecting visited translated blocks from the fuzzing runs

The first step is to collect the translated blocks as seen by Qemu for each of the test cases.
We use a combination of firmwires `--trace-bb-translation` flag and afl-showmap for doing so.
Furthermore, for the shannon basebands, we require the snapshots as generated in V-A.

To collect the basic blocks, simply run:

```
$ ./reached_basic_blocks/01_collect_tbs.sh
```

This will generate multiple log files under `[${EXPERIMENT_ROOT}/V-B_fuzzing_performance/data/01_tb_collection](./data/01_tb_collection)`


### 2) Creating JSON of visited translated blocks

The second step parses the previously generated log files and stores the seen translated blocks for each image and run into a json file using the `02_parse_tbs.py` script.
The script requires as arguments the directory with the log files and the output file.

```
$ ./reached_basic_blocks/02_parse_tbs.py ./data/01_tb_collection/ ./data/02_seen_tbs.json
```

### 3) Converting JSON to a uniquely visited TB file 

The third step is to obtain the *uniquely* visited translated blocks per image, which will allow to generate the translated block <-> basic block mapping in the next step.
Please run the `03_get_bbs_for_image_from_json.py` with the generated json file from the last step, and the output directoy as arguments, e.g.,:

```
$ ./reached_basic_blocks/03a_get_bbs_for_image_from_json.py ./data/02_seen_tbs.json ./data/03_tbs_per_image
```

### 3b,3c) Disassembling at the translated block locations (Shannon Only):

Unlike for MTK, we do not have debug symbols specifying function boundaries for the Shannon baseband.
Hence, we additionally need to start disassembling at the seen translated blocks before calculating the actually reached basic blocks.

For doing so, open Ghidra, with the loaded modem image (use the tooling provied at the [Shannon Baseband](https://github.com/grant-h/ShannonBaseband) repository to do so). Now, add the `reached_basic_blocks` directory to your Ghidra script path, and you should see scripts 3b, 3c, and 4 in the `FirmWireEval` category.

Start with executing `3b_ghidra_disassemble_tbs.py` and a dialog will prompt you to select a file; choose the matching translated_block generated in the last script for the currently opened image.
As this will introduce some 1-byte functions, you will additionally need to run `3c_ghidra_fixup_1_byte_functions.py`.

Note that this step must be run for every analyzed image individually.

### 4) Transforming visited translated blocks to basic blocks

Open Ghidra with the loaded modem file to get the basic blocks for.
If you did not add the `reached_basic_blocks` directory to your script path, please do so now.

Execute the `04_ghidra_postprocess.py` script from within Ghidra. Select the JSON file generated in Step 2 when prompted for it and then select the currently opened image from the drop down list. Note that you may need to add write permissions to the JSON file first, depending on your setup.

This will get the basic blocks for the seen translated blocks in the JSON and *updates* the JSON file. To indicate that translated blocks were already replaced by translated blocks, the variant field will have the `postprocessed` flag set to true.

Like the last step, this step must be run for every analyzed image individually.

Afterwards, you are all set to use the contents from the json files to generate coverage plots!

## Generating per Task Coverage

For estimating the per-task coverage, we deployed two simple heuristics, as described in the Appendix of the paper. For Shannon images, we used the trace entries embedded in the modem file to identify "relevant" functions. For MTK images, we used the included function symbols, to identify "relevant" functions based on their name. We consider all basic blocks as of these functions as potentially reachable code for our fuzzer.

For both approaches, you will need to have the image to analyze opened in Ghidra and the `per_task_coverage` directory added to your Ghidra Script Path.
This time, the scripts will appear in the FirmWirePerTaskEval category.

### Shannon

To establish the per-task coverage for Shannon images, you need to carry out the following steps after opening the image to analyze in Ghidra:

1) Retrieve all possible trace-entries by executing `ShannonTraceEntries.py` from Ghidra. This will create a trace-entries file in the directory from where Ghidra was *started*. The `ShannonTraceEntries.py` file is originally part of the [grant-h/ShannonBaseband](https://github.com/grant-h/ShannonBaseband) repository.
2) If not already done during the reached-basic-block experiment, create a txt file with the uniquely reached translated blocks, using the `get_tbs_for_image_from_json.py` script.
3) Execute `ShannonGetPerTaskStats.py` from Ghidra. This will ask to select the according trace-entries and translated block files, and then automatically identify the per-task coverage for the SM, CC, and LTERRC tasks. The output is printed on the Ghidra python console.

### MTK

To establish the per-task coverage for MTK images, you just need to run the `MTKGetPerTaskStats.py` script from Ghidra after opening the image to analyze.
This script simply scans for function names with the `errc_` prefix and calculates the reached coverage within these functions.