# Fixes functions of length 1 by reanalysis
# @author Marius Muench (@mariusmue)
# @category FirmWireEval

from ghidra.app.cmd.function.CreateFunctionCmd import fixupFunctionBody
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor

fapi = FlatProgramAPI(currentProgram)
dummy_mon = TaskMonitor.DUMMY




function = fapi.getFirstFunction()
while function is not None:
    if function.getBody().getNumAddresses() == 1:
        print("Fixing " + function.toString())
        fixupFunctionBody(currentProgram, function, dummy_mon)
        print("\tThe new size is: %d" % function.getBody().getNumAddresses())


    function = fapi.getFunctionAfter(function)