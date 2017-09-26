from binaryninja import *
from binaryninja.enums import *
from binaryninja.function import *
from picdis18 import matching_opcode, 
import struct
# These functions are wrappers for generating tokens for dissassembly
def TextToken(txt):
    return InstructionTextToken(InstructionTextTokenType.TextToken, txt)


def IntegerToken(num):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken, '#0x%x' % num, value=num)


def SeperatorToken(txt=","):
    return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, txt)


def RegisterToken(txt):
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, txt)


def AddressToken(num):
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, '0x%x' % num, value=num)


def empty_formatter(instr):
    return []


# Opcode to instruction name mapping
InstructionNames = {}

# Opcode to il generator mapping
InstructionLLIL = {}

# Opcode to operand formatter mapping
InstructionFormatters = {}

# Opcode to InstructionInfo modder mapping
# Only used for control flow instruction
InstructionInfoModders = {}

opcodes = [
    #bitpattern, opcode 
    ('1100', 'MOVFF'),
    ('0110010', 'CPFSGT'),
    ('1110110', 'CALL'),
    ('11011', 'RCALL'),
    ('11101111', 'GOTO'),
     ('000000000001001', 'RETURN'),
     ('1111', 'NOP'),
     ('0000000000000000', 'NOP'),
     ('00001101', 'MULW'),
     ('000001', 'DECF'),
     ('001100', 'RETW'),
     ('000000000001001', 'RETURN'),
     

]
#0000010001101110
#0000110111110000
#1000000000000001
two_word_opcodes = [
    'MOVFF',
    'GOTO',
]
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
    iinfo.add_branch(BranchType.CallDestination ,instr.n)

def rcall_formatter(instr):
    return [AddressToken(instr.n)]
InstructionInfoModders['RCALL'] = rcall_modder
InstructionFormatters['RCALL'] = rcall_formatter

def ret_modder(iinfo, instr):
    iinfo.add_branch(BranchType.FunctionReturn)
InstructionInfoModders['RETW'] = ret_modder
InstructionInfoModders['RETURN'] = ret_modder

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
        self.addr = addr
        self.opcode = lookup_opcode(data[:2])
        self.length = 2
        if self.opcode in two_word_opcodes:
            self.length = 4
        self.data = data[:self.length]

        if self.opcode == 'RCALL':
            target = get_bits(self.data, 0, 11)
            target = signed(target, 11)
            target = 2 + 2*target
            self.n = target

    

def get_instruction(data, addr):
    return (True, PIC18F(data, addr))

class PIC18FArch(Architecture):
    name = "PIC18F"
    address_size = 2
    default_int_size = 1
    max_instr_length = 4
    regs = {
        "STKPTR": RegisterInfo("STKPTR", 1),
        "STATUS": RegisterInfo("STATUS", 1),
    }
    stack_pointer = "STKPTR"
    def perform_get_instruction_info(self, data, addr):
        valid, instr = get_instruction(data, addr)
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
        tokens = []
        instr_name = instr.opcode
        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr_name))
        if instr.opcode in InstructionFormatters:
            formatter = InstructionFormatters[instr.opcode]
            extra_tokens = formatter(instr)
            if len(extra_tokens) > 0:
                tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, " ")] + extra_tokens
        return tokens, instr.length
    
    def perform_get_instruction_low_level_il(self, data, addr, il):
        return None

def init_module():
    PIC18FArch.register()

init_module()