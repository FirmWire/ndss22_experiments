#!/usr/bin/env python3

import sys
import json
import os

'''
Used with the following images: 
CP_G973FXXU9FUCD_CP18513696_CL21324211_QB39036441_REV01_user_low_ship.tar.md5

'''


def main(jsonfile, output_directory):
    with open(jsonfile, 'r') as f:
        data = json.load(f)

    os.makedirs(output_directory)

    for image in data:
        bbs = set()

        for name, run in data[image].items():
            if name == 'postprocessed':
                continue
            bbs |= set(run['seen_blocks'])

        with open(f'{output_directory}/translated_blocks_{image}.txt', 'w') as f:
            f.writelines(hex(b)+'\n' for b in sorted(bbs))

    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} json-file output_directory")
        exit(-1)
    main(sys.argv[1], sys.argv[2])

