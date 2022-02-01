import csv
import re
import subprocess
import os.path
import sys
import calendar

from collections import OrderedDict
# note: this script assumes the lte_rrc fuzzer was run with debug output compiled


CRASHES=[
    'GSM_CC_Bearer_Crash_MEM_GUARD_G973F_ASG8.bin',
    'GSM_CC_SETUP_MSG_ProAsn_PREFETCH_ABORT_G973F_CTD1.bin',
    'GSM_SM_PREFETCH_ABORT_G950_AQI7.bin',
    'LTE_RRC_LRRCConnectionReconfiguration_v890_IEs_PREFETCH_ABORT_G973F_CTD1.bin',
    'LTE_RRC_ProAsn_Encode_MEM_GUARD_G973F_9FUCD.bin',
    'LTE_RRC_RRCConnectionReconfiguration_SIB2_PREFETCH_ABORT_G973F_9FUCD.bin'
]


# year and month is encoded in part of the image name:
# https://forum.xda-developers.com/t/ref-samsung-firmware-naming-convention-and-explanation.1356325/
year  = lambda img: ord(img.split('_')[1][-3]) - 0x40 + 2000
month = lambda img: ord(img.split('_')[1][-2]) - 0x40


def get_image_dates(image_dir):
    images = OrderedDict()
    images['CP_G930'] = {}
    images['CP_G935'] = {}
    images['CP_G950'] = {}
    images['CP_G955'] = {}
    images['CP_G960'] = {}
    images['CP_G970'] = {}
    images['CP_G973'] = {}
    for image in os.listdir(image_dir):
        if image.endswith('tar.md5') is False:
            continue
        release_date = f'{year(image)}{month(image):02d}'
        images[image[:7]][image] = {'date': release_date}
    return images


def get_crash_type(crash_lines):

    if 'DATA ABORT' in crash_lines:
        type = 'DA'
    elif 'PREFETCH ABORT' in crash_lines:
        type = 'PA'

    elif 'PAL_MEM_GUARD_CORRUPTION' in crash_lines:
        type = 'MEM'
    elif 'RESET CALLED' in crash_lines:
        type = 'R'
    elif 'TIMEOUT' in crash_lines :
        type = 'T'
    elif '[+] Event set' in crash_lines \
       or ' CC ==> MM_REL_REQ' in crash_lines \
       or 'ati_FwHandlers_HandleUnsolicitedMessage' in crash_lines \
       or ' NS <== NS_DM_NAS_CC_INFO_EVENT' in crash_lines \
       or 'GMMSM_ESTABLISH_REQ' in crash_lines \
       or 'NS_DM_RRC_UECAPA_INFO_EVENT' in crash_lines \
       or 'DbgSAP: ServLock Reg(SERVICE_UNLOCKED)' in crash_lines \
       or 'BTL' in crash_lines \
       or 'AFL_LTE_RRC' in crash_lines \
       or 'CALL_CONFIRMED_REQ' in crash_lines \
       or 'OS_Schedule_Task' in crash_lines:
        type = 'N'
    else:
        type = '?'
    return type

def image_shortname(name):
    return name.split('_')[1]

def crashtypes_to_latex(ct):
    fill_len = len('\checkmark') + 1

    ret = []
    for c in ct:
        if c.isnumeric():
            year = c[2:4]
            month = int(c[4:])
            month = calendar.month_abbr[month]
            ret += [ f'{month}\'{year}' ]
        elif c == 'N':
            ret += [' '.rjust(fill_len) ]
        elif c == 'T':
            ret += ['T'.rjust(fill_len) ]
        elif c in ['PA', 'MEM', 'DA', 'R']:
            ret += ['\checkmark ']
        else:
            ret += [c]
    return ret

cp2phone = {
    'CP_G930': 'Galaxy S7',
    'CP_G935': 'Galaxy S7 Edge',
    'CP_G950': 'Galaxy S8',
    'CP_G955': 'Galaxy S8+',
    'CP_G960': 'Galaxy S9',
    'CP_G970': 'Galaxy S10',
    'CP_G973': 'Galaxy S10e'
}

def main(image_dir, log_dir, output_file):
    f = open(output_file, 'w')
    w = csv.writer(f)
    w.writerow(['image', 'release date'] + CRASHES)


    images = get_image_dates(image_dir)

    for model, image_data in images.items():
        sorted_images = sorted(image_data, key=lambda x: image_data[x]['date'])


        for image in sorted_images:
            image_data[image]['crashes'] = []
            if not os.path.exists(f'{log_dir}/{image}.log'):
                crash_types_flat = ['-'] * 7
                row = [image_shortname(image), image_data[image]['date']]  + crash_types_flat
                w.writerow(row)
                continue

            with open(f'{log_dir}/{image}.log', 'r') as f:
                log_text = f.read()

            for crash_run_log in log_text.split('\n\n\n\n'):
                if crash_run_log == '':
                    continue

                crash_lines = crash_run_log.split('\n')
                # Below line may be inserted by timeout's stdout, let's remove it
                if 'timeout: the monitored command dumped core' in crash_lines:
                    crash_lines.remove('timeout: the monitored command dumped core')
                crash_name = crash_lines[-2]
                crash_error = crash_lines[-4] + '\n' + crash_lines[-3]
                type = get_crash_type(crash_error)
                #import IPython; IPython.embed()


                image_data[image]['crashes'] += [(crash_name, type)]


            crash_types_flat = [c[1] for c in image_data[image]['crashes']]

            crash_types_simplified = []
            row = [image_shortname(image), image_data[image]['date']]  + crash_types_flat
            w.writerow(row)

    sys.exit()

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} image_directory logfile_directory output_file")
        exit(-1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])

