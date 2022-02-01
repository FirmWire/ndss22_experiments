#!/usr/bin/env python3
from subprocess import Popen, PIPE, STDOUT
import argparse
import os
import sys
import glob

BUGS = {
        "CC1" : {
            'filename':'GSM_CC_Bearer_Crash_MEM_GUARD_G973F_ASG8.bin',
            'fuzzer': 'gsm_cc',
        },
        "CC2" : { 
            'filename': 'GSM_CC_SETUP_MSG_ProAsn_PREFETCH_ABORT_G973F_CTD1.bin',
            'fuzzer': 'gsm_cc',
        },
        'SM': {
            'filename': 'GSM_SM_PREFETCH_ABORT_G950_AQI7.bin',
            'fuzzer': 'gsm_sm',
        },
        "RRC1": {
            'filename': 'LTE_RRC_LRRCConnectionReconfiguration_v890_IEs_PREFETCH_ABORT_G973F_CTD1.bin',
            'fuzzer': 'lte_rrc',
        },
        "RRC2": {
            'filename': 'LTE_RRC_ProAsn_Encode_MEM_GUARD_G973F_9FUCD.bin',
            'fuzzer': 'lte_rrc',
        },
        "RRC3": {
            'filename': 'LTE_RRC_RRCConnectionReconfiguration_SIB2_PREFETCH_ABORT_G973F_9FUCD.bin',
            'fuzzer': 'lte_rrc',
        },
        "RRC4": {
            'filename': 'LTE_RRC_MTK_MCCH_DoubleFree_A41_ATE1.bin',
            'fuzzer': 'lte_rrc',
        }
    }

def exec_firmwire(args):
    exe_args = ""
    Popen()
    pass

def main():
    #export EXPERIMENT_ROOT=path/to/your/ndss22_experiments-repository
    #export FIRMWIRE_ROOT=/path/to/your/firmwire-repository

    if 'EXPERIMENT_ROOT' not in os.environ:
        print("You must set the env var EXPERIMENT_ROOT to the NDSS experiments repo. See readme")
        sys.exit(1)

    if 'FIRMWIRE_ROOT' not in os.environ:
        print("You must set the env var FIRMWIRE_ROOT to the FirmWire git directory. See readme")
        sys.exit(1)

    ndss_dir = os.path.abspath(os.environ['EXPERIMENT_ROOT'])
    firmwire_dir = os.path.abspath(os.environ['FIRMWIRE_ROOT'])
    firmwire_path = os.path.join(firmwire_dir, 'firmwire.py')

    if not os.path.exists(firmwire_path):
        print('Missing ./firmwire.py. Check FIRMWIRE_ROOT.')
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware-override")
    parser.add_argument("bugname", choices=sorted(BUGS.keys()))

    args = parser.parse_args()

    bug_filename = BUGS[args.bugname]["filename"]
    bug_path = os.path.join(ndss_dir, "V-D_vulnerabilities/crashes", bug_filename)

    if not os.path.exists(bug_path):
        print('Invalid path %s. Check EXPERIMENT_ROOT.' % EXPERIMENT_ROOT)
        sys.exit(1)

    print("[+] For bug %s, using crasher %s" % (args.bugname, bug_path))

    model, version = bug_filename.split("_")[-2:]
    version = version.split(".")[0]

    print("Model %s, Version %s" % (model, version))

    if args.firmware_override:
        firmware_path = args.firmware_override
    else:
        files = glob.glob(os.path.join(ndss_dir, 'firmware_samples/*%s*%s*' % (model, version)))

        if len(files) == 0:
            print('Missing firmware')
            sys.exit(1)

        firmware_path = files[0]

    if not os.path.exists(firmware_path):
        print("Missing firmware %s" %(firmware_path))
        sys.exit(1)

    fuzzer_name = BUGS[args.bugname]["fuzzer"]
    args = [firmwire_path, "-w", "SCRATCH", "--fuzz-triage", fuzzer_name, "--fuzz-input", bug_path, firmware_path]

    print("Using firmware %s" % (firmware_path))
    print("Args: %s" % (args))

    proc = Popen(args, cwd=firmwire_dir)
    proc.communicate()

    print(proc.returncode)

if __name__ == "__main__":
    main()
