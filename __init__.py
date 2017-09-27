from binaryninja import *
from binaryninja.enums import *
from binaryninja.function import *
from picdis18 import assembly_line,read_registry_names 
import struct

# Opcode to instruction name mapping
InstructionNames = {}

# Opcode to il generator mapping
InstructionLLIL = {}

# Opcode to operand formatter mapping
InstructionFormatters = {}

# Opcode to InstructionInfo modder mapping
# Only used for control flow instruction
InstructionInfoModders = {}

def get_bits(bytes, r_offset, size):
    num, = struct.unpack('!H', bytes)
    num >>= r_offset
    num &= ((1 << size)-1)
    return num

def signed(bits, bits_size):
    if 1 << (bits_size - 1) & bits == 0:
        return bits
    needed_bits = 16-bits_size
    mask = ((1 << needed_bits) - 1) << bits_size
    result, = struct.unpack('!h', struct.pack('!H', mask | bits))
    return result

def rcall_modder(iinfo, instr):
    print 'Modding rcall'
    iinfo.add_branch(BranchType.CallDestination ,instr.target)

InstructionInfoModders['rcall'] = rcall_modder

def ret_modder(iinfo, instr):
    print 'Modding retw or return'
    iinfo.add_branch(BranchType.FunctionReturn)
InstructionInfoModders['retw'] = ret_modder
InstructionInfoModders['return'] = ret_modder

def lookup_opcode(data):
    for prefix, opcode in opcodes:
        prefix_num = int(prefix, 2)
        shift_size = 16 - len(prefix)
        data_bits, = struct.unpack('!H', data[0:2])
        if (data_bits >> shift_size) == prefix_num:
            return opcode
    return 'UNK'

class PIC18F:
    def __init__(self, data, addr):
        if len(data) < 4:
            data += struct.pack('!HH', 0, 0)
        self.addr = addr
        w1, w2 = struct.unpack('!HH', data[:4])
        self.opcode, self.length, self.target, self.disassembly = assembly_line(addr, w1, w2)
        self.data = data[:self.length]
    

def get_instruction(data, addr):
    return (True, PIC18F(data, addr))

class PIC18FArch(Architecture):
    name = "PIC18F"
    address_size = 2
    default_int_size = 1
    max_instr_length = 4
    regs = {}
    for regname in read_registry_names().values():
        regs[regname] = RegisterInfo(regname, 1)
    stack_pointer = "STKPTR"
    def perform_get_instruction_info(self, data, addr):
        valid, instr = get_instruction(data, addr)
        print 'Trying %s at 0x%x' % (instr.opcode, instr.addr)
        result = InstructionInfo()
        if valid:
            result.length = instr.length
            if instr.opcode in InstructionInfoModders:
                InstructionInfoModders[instr.opcode](result, instr)
            return result
        else:
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None

    def perform_get_instruction_text(self, data, addr):
        valid, instr = get_instruction(data, addr)
        if not valid:
            # This is _EXCEEDINGLY_ important to return on failure.
            # Things will break in creative ways if anything other than None
            # is returned for invalid data
            return None
        return instr.disassembly, instr.length
    
    def perform_get_instruction_low_level_il(self, data, addr, il):
        return None

def init_module():
    PIC18FArch.register()

init_module()