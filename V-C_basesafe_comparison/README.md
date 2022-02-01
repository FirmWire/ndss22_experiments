# Comparison with the state of the art: BaseSafe

This subdirectory holds two different BaseSafe harnesses: One manually created for fuzzing the GSM CC task, and one which automatically starts emulation from snapshots taken inside firmwire.
These snapshots are slightly different from the usual firmwire snapshots, to accomodate the needs of the BaseSafe harness. To create such a snapshot, use the supplied `create_basesafe_snapshot.py` script from FirmWire's interactive mode.

## Setup

To install the dependencies and build the harnesses, just run `build.sh` (tested on Ubuntu 20.04).

## Fuzzing

To start fuzzing, enter the desired directory and execute:
```
$ make fuzz
```

Additionally, in the case of the `firmwire-basesafe` directory, you can switch the target harness/snapshot by using the `switch_target.sh` file, e.g.:
```
$ switch_target.sh lte_rrc
```

## Q & A

### Q: Why do I need a fixed AFL++ version?

BaseSafe uses AFL++'s Unicorn bindings. As these changed over time, we decided to provide the very same AFL++ version as we used in our evaluation.