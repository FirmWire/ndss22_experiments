.PHONY: all fuzz afl-fuzz run-debug debug release run

ifdef OUTDIR
OUT := $(OUTDIR)
else
OUT := out
endif


all: ../target/release/firmwire_basesafe

afl-fuzz: ../AFLplusplus/afl-fuzz
../AFLplusplus/afl-fuzz:
	../build.sh

clean:
	cargo clean

../target/release/firmwire_basesafe: ../AFLplusplus/afl-fuzz ./src/main.rs
	cargo build --bin firmwire_basesafe --release

release: ../target/release/firmwire_basesafe snapshot
run: release
	../target/release/firmwire_basesafe ./in/a
	
debug: ../target/debug/firmwire_basesafe snapshot
run-debug: debug
	../target/debug/firmwire_basesafe ./in/a
	
../target/debug/firmwire_basesafe: ../AFLplusplus/afl-fuzz ./src/main.rs
	cargo build

snapshot: ./snapshot.tar.gz
	rm -rf ./snapshot | true
	tar -xvzf ./snapshot.tar.gz

fuzz: all afl-fuzz snapshot
	#rm -rf ./out
	AFL_AUTORESUME=1 SKIP_BIN_CHECK=1 AFL_COMPCOV_LEVEL=2 ../AFLplusplus/afl-fuzz -t 10000 -V 86400 -s 1 -i in -o $(OUT) -- ../target/release/firmwire_basesafe @@
