from binaryninja import Architecture, RegisterInfo, InstructionInfo, InstructionTextToken, lowlevelil

from typing import Tuple, Optional, List

from .disassembler import Disassembler, Disassembler35

"""
The archictecture for python bytecode version [3.6; 3.10+]
"""
class Python(Architecture):
    name = 'Python-bytecode'

    regs = {'SP': RegisterInfo('SP', 2)}
    stack_pointer = 'SP'

    max_instr_length = 2 # changed in python3.6, each instruction is now 2 bytes long

    def __init__(self):
        super().__init__()
        self.disassembler = Disassembler()

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo:
        if not data:
            return None

        return self.disassembler.disasm(data, addr)


    def get_instruction_text(self, data, addr) -> Tuple[List[InstructionTextToken], int]:
        if not data:
            return None
        try:
            return self.disassembler.get_instruction_text(data, addr)
        except IndexError:
            return [], 2

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction):
        return None


    def convert_to_nop(self, data: bytes, addr: int = 0) -> Optional[bytes]:
        if not data:
            return None
        
        return self.disassembler.get_nop()


    def invert_branch(self, data: bytes, addr: int = 0) -> Optional[bytes]:
        if not data:
            return None
        
        return self.disassembler.invert_branch(data, addr)
    

class Python35(Python):
    name = 'Python-bytecode35'
    max_instr_length = 3

    def __init__(self):
        super().__init__()
        self.disassembler = Disassembler35()

    def get_instruction_text(self, data, addr) -> Tuple[List[InstructionTextToken], int]:
        if not data:
            return None
        try:
            return self.disassembler.get_instruction_text(data, addr)
        except IndexError:
            return [], 1
        
class Python34(Python35):
    name = 'Python-bytecode34'

class Python33(Python35):
    name = 'Python-bytecode33'

class Python32(Python35):
    name = 'Python-bytecode32'

class Python31(Python35):
    name = 'Python-bytecode31'

class Python30(Python35):
    name = 'Python-bytecode30'