from binaryninja import Architecture, RegisterInfo, InstructionInfo

from typing import Tuple
from .disassembler import Disassembler

class Python(Architecture):
    name = 'Python-bytecode'

    regs = {'SP': RegisterInfo('SP', 2)}
    stack_pointer = 'SP'

    max_instr_length = 3 # changed in python3.6, each instruction is now 2 bytes long

    def __init__(self):
        super().__init__()
        self.disassembler = Disassembler()


    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo:
        if not data:
            return None

        return self.disassembler.disasm(data, addr)


    def get_instruction_text(self, data, addr) -> Tuple[str, int]:
        if not data:
            return None

        return self.disassembler.get_instruction_text(data, addr)


    def get_instruction_low_level_il(self, data, addr, il):
        return None