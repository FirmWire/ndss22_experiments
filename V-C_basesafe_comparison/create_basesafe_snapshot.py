import os

'''
This script is a quick and dirty raw-dump of memory regions, together with a
metadata.csv. It is used to create the initial memory layout for unicorn-based
(basesafe) fuzzing.

The script is meant to be run directly after start of firmwire, e.g.:
$ jupyter-console --existing 
In [1]:   import create_basesafe_snapshot
In [2]:   create_basesafe_snapshot.do_snapshot('/tmp/snapshot', self)
'''


def do_snapshot(path, sm):
    os.mkdir(path)
    qemu = sm.qemu

    bp = sm.fuzz_task_address + sm.fuzz_task.resolve_symbol('getWork') & 0xfffffffe
    qemu.set_breakpoint(bp)
    qemu.cont()
    qemu.wait()
    

    with open(f'{path}/ranges.csv', 'w') as meta:
        for mr in sorted(qemu.avatar.memory_ranges):
            mr = mr.data
            name = mr.name
            print(f'[*] dumping {name}')
            address = mr.address
            size = mr.size
            with open(f'{path}/{name}', 'wb') as f:
                f.write(qemu.read_memory(mr.address, mr.size,raw=True))
                meta.write(f'{name},{address},{size},{mr.permissions}\n')
    with open(f'{path}/regs.csv', 'w') as regfile:
        for reg in qemu.protocols.registers.get_register_names():
            if reg == '':
                continue
            regfile.write(f'{reg},{qemu.read_register(reg)}\n')
    with open(f'{path}/symbols.csv', 'w') as symbfile:
        base = sm.fuzz_task_address
        for s in ['startWork', 'doneWork','getWork', 'afl_buf']:
            addr = sm.fuzz_task_address + sm.fuzz_task.resolve_symbol(s)
            symbfile.write(f'{s},{addr}\n')
        symbfile.write(f'OS_fatal_error,{sm.symbol_table.lookup("OS_fatal_error").address}\n')







