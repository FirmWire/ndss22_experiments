.PHONY: all fuzz afl-fuzz run-debug debug release run

ifdef OUTDIR
OUT := $(OUTDIR)
else
OUT := out
endif

all: ../target/release/manual_gsm_cc

afl-fuzz: ../AFLplusplus/afl-fuzz
../AFLplusplus/afl-fuzz:
	../build.sh

clean:
	cargo clean

../target/release/manual_gsm_cc: ../AFLplusplus/afl-fuzz ./src/main.rs
	cargo build --bin manual_gsm_cc --release

release: ../target/release/manual_gsm_cc modem.bin
run: release
	../target/release/manual_gsm_cc ./in/a
	
debug: ../target/debug/manual_gsm_cc modem.bin
run-debug: debug
	../target/debug/manual_gsm_cc ./in/a
	
../target/debug/manual_gsm_cc: ../AFLplusplus/afl-fuzz ./src/main.rs
	cargo build

modem.bin.lz4: CP_G973FXXU9FUCD_CP18513696_CL21324211_QB39036441_REV01_user_low_ship.tar.md5
	tar -xvf CP_G973FXXU9FUCD_CP18513696_CL21324211_QB39036441_REV01_user_low_ship.tar.md5

modem.bin: modem.bin.lz4
	lz4 -d modem.bin.lz4

fuzz: all afl-fuzz modem.bin
	#rm -rf ./out
	AFL_AUTORESUME=1 SKIP_BIN_CHECK=1 AFL_COMPCOV_LEVEL=2 ../AFLplusplus/afl-fuzz -V 86400 -s 1 -i in -o $(OUT) -- ../target/release/manual_gsm_cc @@
