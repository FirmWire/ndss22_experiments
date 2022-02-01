#/bin/sh

FUZZERS=('gsm_sm gsm_cc lte_rrc')

if [[ ! " ${FUZZERS[*]} " =~ " $1 " ]]; then
    echo "[-] Please select a valid fuzzer! (Possible fuzzers are: $FUZZERS)"
    exit
fi

echo "[+] Cleaning up prior contents"
rm -r snapshot
unlink snapshot.tar.gz
unlink in

echo "[+] Creating new symlinks"
ln -s snapshot_$1.tar.gz snapshot.tar.gz
ln -s in_$1 in

echo "[+] All done!"
