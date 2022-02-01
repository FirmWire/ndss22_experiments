#!/usr/bin/env python3

import json
import os


def main(logfile_dir, output_json_file):

    variants = {}

    current_run = None
    current_testcase = None

    for logfile in os.listdir(logfile_dir):

        with open(f'{logfile_dir}/{logfile}', "r") as f:
            for line in f.readlines():
                # Processing ../../results/CP_G970FXXU3BSKL_CP14451478_CL17369399_QB27459164_REV01_user_low_ship.tar.md5/run_1/main/queue/id:004586,src:001262,time:54165108,op:havoc,rep:2
                if line.startswith("Processing "):
                    values = line.split("/")[-7:]
                    variant = values[1]
                    
                    
                    run = values[2]
                    item = values[-1].strip()
                    try:
                        time = int(item.split("time:")[1].split(",")[0])
                    except Exception as ex:
                        time = 0

                    variant_content = variants.setdefault(variant, {})
                    variant_content['postprocessed'] = False
                    run_content = variant_content.setdefault(run, {"seen_blocks": set()})
                    #if run_content is not current_run:
                    #    print("Working on new run", variant, run)
                    current_run = run_content
                    current_testcase = run_content.setdefault(item, {})
                    current_testcase["time"] = time
                    current_testcase["new_blocks"] = 0
                    current_testcase["id"] = len(run_content.keys())
                    current_testcase["new_block_list"] = []


                # NEW BLOCK: 0x408151d2
                if line.startswith("NEW BLOCK: "):
                    if current_testcase is None:
                        #print("New block before 'afl-showmap processing output' - ignored", line)
                        continue
                    values = line.split(" ")
                    block_id = int(values[2].strip(), 16)
                    #translated_blocks = current_testcase.setdefault("translated_blocks", list())
                    #translated_blocks.append(block_id)
                    if block_id not in current_run["seen_blocks"]:
                        current_run["seen_blocks"].add(block_id)
                        current_testcase["new_blocks"] += 1
                        current_testcase["new_block_list"].append(block_id)
                    #todo: finish up
            
                # ^[[1;92m[+] ^[[0mProcessed 3973 input files.^[[0m"
                if "Processed" in line and "input files." in line:
                    current_testcase = None

    with open(output_json_file, 'w') as f:
        f.write(json.dumps(variants, default=lambda o: [b for b in o]))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <logfile_directory> <output_json_file>")
        exit(-1)
    main(sys.argv[1], sys.argv[2])
