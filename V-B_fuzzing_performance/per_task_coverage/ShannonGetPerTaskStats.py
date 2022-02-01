# Quick and dirty script to approximate per task coverage for Shannon images
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
    trace_entry_file = str(askFile("CHOOSE TRACE ENTRY FILE", "TraceEntryFile"))
    basic_block_file = str(askFile("CHOOSE BASIC BLOCK FILE", "Basic Block File"))
    #magic_string = askChoice(
        #"Choice", "Please choose Trace Subset", ["/CC/", "/SM/", "/LteRrc/"], "/CC/"
    #)

except IllegalArgumentException as error:
    Msg.warn(self, "Error during headless processing: " + error.toString())
    exit()

trace_entry_map = {}


fapi = FlatProgramAPI(currentProgram)
bbm = BasicBlockModel(currentProgram)
dummy_mon = TaskMonitor.DUMMY


for task in ["/CC/", "/SM/", "/LteRrc/"]:
    magic_string = task
    with open(trace_entry_file, "r") as f:
        trace_entries = f.read()
        trace_entry_addresses = re.findall(
            "\[.*?\] \[(.*?)\].*" + magic_string, trace_entries
        )
        trace_entry_addresses = [int(t, 16) for t in trace_entry_addresses]

    no_xrefs = set()
    basic_blocks = set()
    covered_functions = set()

    # Step 1: get the basic_blocks of interest
    for addr in trace_entry_addresses:
        addr = fapi.toAddr(addr)
        refs = fapi.getReferencesTo(addr)
        if len(refs) == 0:
            no_xrefs.add(addr2int(addr))
            continue
        # ARM uses double dereferences
        for ref in refs:
            ptr_refs = fapi.getReferencesTo(ref.fromAddress)
            for ptr_ref in ptr_refs:
                fn = fapi.getFunctionContaining(ptr_ref.fromAddress)
                if fn == None:
                    fn = UndefinedFunction.findFunction(
                        currentProgram, ptr_ref.fromAddress, dummy_mon
                    )
                    print("Found a non-defined function, fixing up ...")
                    name = "FUN_" + fn.getName().split('_')[1]
                    print("Et voila! There is now: " + name)
                    fapi.createFunction(fn.getEntryPoint(), name)

                else:
                    addrSet = fn.getBody()
                fn_addr = addr2int(addrSet.getMinAddress())
                if fn_addr in covered_functions:
                    continue
                #print(fn)
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
    with open(basic_block_file, 'r') as f:

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
    print("Missing XREFS: %d" % len(no_xrefs))
    print("Total Trace Entries: %d" % len(trace_entry_addresses))

    print("Iterated over %d translated blocks" % n_translated)
    print("Failed Basic Blocks %d" % n_failed_translated)
    print("Covered: %d / %d basic blocks (%0.2f %%)" %( len(covered_bbs),
                                                       len(basic_blocks),
                                                       (float(len(covered_bbs))/ len(basic_blocks)) * 100 ))

