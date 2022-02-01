# Postprocess a json file from Firmwire experiments.
# Main purpose is to translate qemu translated blocks to ghidra basic blocks.
# @author Marius Muench (@mariusmue)
# @category FirmWireEval

import json


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor
from ghidra.util import UndefinedFunction
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import ArmDisassembleCommand

from java.lang import IllegalArgumentException

addr2int = lambda x: int(x.toString(), 16)


try:
    jsonfile = str(askFile("CHOOSE EXPERIMENT FILE", "json file"))

    with open(jsonfile, 'r') as f:
        data = json.load(f)


    modem = askChoice(
        "Choice", "Please choose modem file", [m for m in data.keys()], data.keys()[0]
    )
    runs = data[modem]

except IllegalArgumentException as error:
    Msg.warn(self, "Error during headless processing: " + error.toString())
    exit()

fapi = FlatProgramAPI(currentProgram)
bbm = BasicBlockModel(currentProgram)
dummy_mon = TaskMonitor.DUMMY


# step 1: assemble ifneedbe
bbs = set()

# dict mapping qemu-tbs to ghidra-bbs
bb_mapping = {}

discard_blocks = set() # due to runtime loading, some BBs may not be found in Ghidra
for run_name, run in runs.iteritems():
    if run_name == 'postprocessed':
        runs[run_name] = True
        continue

    print("Analyzing %s" % run_name)
    bb_run = set(run['seen_blocks'])
    for bb in bb_run:
        if bb in bb_mapping or bb in discard_blocks:
            continue
        

        addr = fapi.toAddr(bb)
        addrSet = AddressSet(addr)
        bbs = bbm.getCodeBlocksContaining(addrSet, dummy_mon)

        n_bbs = 0
        while bbs.hasNext():
            ghidra_bb = bbs.next()
            bb_mapping[bb] = int(ghidra_bb.firstStartAddress.toString(), 16)
            n_bbs += 1
        if n_bbs == 0:
            print("Couldn't find block for 0x%s - Is everything alright?" % addr.toString())
            discard_blocks.add(bb)
        elif n_bbs > 1:
            print("Something went horrible wrong")

    # apply the results to the json
    print("discarded %d/%d blocks" % (len(discard_blocks), len(run['seen_blocks'])))

    # This conversion madness is to uniqify the seen blocks
    run['seen_blocks'] = list(set([bb_mapping[b] for b in bb_run-discard_blocks]))

    run_discard_blocks = discard_blocks.copy() # we want to discard blocks we already saw in this run when iterating over the trace entries
    for id, trace_entry in run.iteritems():
        if id == 'seen_blocks':
            continue
        blocks = set([bb_mapping[b] for b in set(trace_entry['new_block_list']) - discard_blocks])
        trace_entry['new_block_list'] = list(blocks)
        trace_entry['new_blocks'] = len(trace_entry['new_block_list'])
        run_discard_blocks |= set(blocks)
with open(jsonfile, 'w') as f:
    json.dump(data, f)
