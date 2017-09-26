from binaryninja.enums import *
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
