import requests
import sys
import re

from os.path import basename
import threading

TARGETS = [
        'https://www.sammobile.com/samsung/galaxy-s7/firmware/SM-G930F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-s7-edge/firmware/SM-G935F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-s8/firmware/SM-G950F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-s8-plus/firmware/SM-G955F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-s9/firmware/SM-G960F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-s10e/firmware/SM-G970F/DBT/',
         'https://www.sammobile.com/samsung/galaxy-s10/firmware/SM-G973F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-a41/firmware/SM-A415F/DBT/',
        'https://www.sammobile.com/samsung/galaxy-a10s/firmware/SM-A107F/MBC/'
]

OUT_DIR='.'


def dl_one(s, dl_url):
    print(f'[+] Start downloading {dl_url}')
    r = s.get(dl_url, stream=True)
    with open(f'{OUT_DIR}/{basename(dl_url)}','wb') as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)
    print(f'[+] Finished {dl_url}')


def main(user, password):
    s = requests.Session()


    s.get('https://www.sammobile.com/login/?login=false')
    data = { 'pwd': password,
            'log': user,
            'rememberme':  'forever',
            'action': "sammobile_login"
           }

    r = s.post("https://www.sammobile.com/login/", data=data)
    assert r.status_code == 200

    jobs = []


    for t in TARGETS:
        r = s.get(t)
        fw_urls = re.findall(t+'/?download/\w*?/\d*/', r.text)
        for fw_url in fw_urls:
            r = s.get(fw_url)
            m = re.search('href="(.*.zip)"', r.text)
            
            dl_url = m.groups()[0]
            print("enqueing thread" + dl_url)
            t = threading.Thread(target=dl_one, args=(s, dl_url))
            jobs.append(t)

        for j in jobs:
            j.start()

        for j in jobs:
            j.join()
        print("[+] Finished downloading for {TARGETS}")




if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

