# Disassemble at a given location of addresses
# @author Marius Muench (@mariusmue)
# @category FirmWireEval

import sys
import re


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor
from ghidra.util import UndefinedFunction
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import ArmDisassembleCommand

from java.lang import IllegalArgumentException

addr2int = lambda x: int(x.toString(), 16)


try:
    translated_block_file = str(askFile("CHOOSE TRANSLATED BLOCK FILE", "Translated Block File"))


except IllegalArgumentException as error:
    Msg.warn(self, "Error during headless processing: " + error.toString())
    exit()

fapi = FlatProgramAPI(currentProgram)
bbm = BasicBlockModel(currentProgram)
dummy_mon = TaskMonitor.DUMMY


n_addrs = 0
n_disassembled = 0
with open(translated_block_file, 'r') as f:

    for addr in f.readlines():
        n_addrs += 1
        addr = fapi.toAddr(addr)
        addrSet = AddressSet(addr)
        bbs = bbm.getCodeBlocksContaining(addrSet, dummy_mon)
        n_bbs = 0
        while bbs.hasNext():
            bb = bbs.next()
            n_bbs += 1
        if n_bbs != 1:
            print("Disassembling at 0x%s" % addr.toString())
            cmd = ArmDisassembleCommand(addr, None, True)
            cmd.applyTo(currentProgram, dummy_mon)
            n_disassembled += 1
print("Finished! Assembled %d new blocks, over a total of %d visited blocks" %( n_disassembled, n_addrs))
