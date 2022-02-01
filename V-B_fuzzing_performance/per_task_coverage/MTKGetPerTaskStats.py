# Quick and dirty script to get per Task Coverage for MTK images  based on a translated block file
# @author Marius Muench (@mariusmue)
# @category FirmWirePerTaskEval

import sys
import re

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor
from ghidra.util import UndefinedFunction
from ghidra.program.model.address import AddressSet

from java.lang import IllegalArgumentException

addr2int = lambda x: int(x.toString(), 16)


try:
    translated_block_file = str(askFile("CHOOSE TRANSLATED BLOCK FILE", "Translated Block File"))

except IllegalArgumentException as error:
    Msg.warn(self, "Error during headless processing: " + error.toString())
    exit()

trace_entry_map = {}


fapi = FlatProgramAPI(currentProgram)
bbm = BasicBlockModel(currentProgram)
dummy_mon = TaskMonitor.DUMMY

fn_mgr = currentProgram.getFunctionManager()

for task in ["errc"]:
    basic_blocks = set()
    covered_functions = set()

    # Step1: Get Functions of interes
    for fn in fn_mgr.getFunctions(True):

        # Heuristic: Function name matching the task?
        if fn.getName().lower().startswith(task):

            addrSet = fn.getBody()
            fn_addr = addr2int(addrSet.getMinAddress())
            if fn_addr in covered_functions:
                continue

            bbs = bbm.getCodeBlocksContaining(addrSet, dummy_mon)
            while bbs.hasNext():
                bb = bbs.next()
                basic_blocks.add(addr2int(bb.firstStartAddress))
            covered_functions.add(fn_addr)

    # Step2: iterate over the seen Translated Blocks and map them to the basic blocks
    n_translated = 0
    n_failed_translated = 0
    n_bbs = 0
    covered_bbs = set()
    with open(translated_block_file, 'r') as f:

        for addr in f.readlines():
            addr = fapi.toAddr(addr)
            addrSet = AddressSet(addr)
            bbs = bbm.getCodeBlocksContaining(addrSet, dummy_mon)
            n_bbs = 0
            while bbs.hasNext():
                bb = bbs.next()
                bb_addr = addr2int(bb.firstStartAddress)
                if bb_addr in basic_blocks:
                    covered_bbs.add(bb_addr)
                n_bbs += 1
            if n_bbs < 1:
                n_failed_translated +=1
                #print("Couldn't find block for 0x%s - Is everything alright?" % addr.toString())
            n_translated += 1

    print("Statistics for %s (%s)" % (currentProgram.getName(), task))

    print("Covered function: %d" % len(covered_functions))
    print("Found Basic Blocks %d" % len(basic_blocks))

    print("Iterated over %d translated blocks" % n_translated)
    print("Failed Basic Blocks %d" % n_failed_translated)
    print("Covered: %d / %d basic blocks (%0.2f %%)" %( len(covered_bbs),
                                                       len(basic_blocks),
                                                       (float(len(covered_bbs))/ len(basic_blocks)) * 100 ))

