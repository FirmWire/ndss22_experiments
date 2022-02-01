import struct

def emit_trace_entry_address(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]
    te_addr = self.qemu.pypanda.virtual_memory_read(cpustate, r0, 4)
    te_addr = struct.unpack('<I', te_addr)[0]
    

    if te_addr not in self.visited_trace_entries:
        self.visited_trace_entries.add(te_addr)
        with open('visited_trace_entries.txt', 'a') as f:
            f.write('{:x}\n'.format(te_addr))


def register_log_hook(sm):
    logprintf_addr = sm.symbol_table.lookup('log_printf').address
    logprintf2_addr = sm.symbol_table.lookup('log_printf2').address
    
    try:
        with open('visited_trace_entries.txt', 'r') as f:
            trace_entries = f.readlines()
    except FileNotFoundError:
        trace_entries = []
    sm.visited_trace_entries = set([int(te, 16) for te in trace_entries])
    sm.add_panda_hook(logprintf_addr, emit_trace_entry_address)
    sm.add_panda_hook(logprintf2_addr, emit_trace_entry_address)
