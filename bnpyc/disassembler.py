from binaryninja import BinaryView, InstructionInfo, BranchType, InstructionTextToken, InstructionTextTokenType
from binaryninjaui import UIContext

from typing import Tuple, List

from .pycview import PycInfo

"""
The Disassembler for python bytecode version [3.6; 3.10+]
"""
class Disassembler:
    def __init__(self):
        self.bv: BinaryView = None
        self.loaded_function_names: List[str] = []
        self.jump_instruction_length = 2


    def set_bv(self) -> bool:    
        ac = UIContext.activeContext()
        if ac is None:
            ac = UIContext.allContexts()[0]

        cv = ac.getCurrentViewFrame()
        if cv is None:
            return False

        self.bv = cv.getCurrentBinaryView()
            
        if self.bv is None:
            return False

        return self.bv.session_data.get('pycinfos') != None # is it the right bv ?


    def setup(self):
        while not self.set_bv():
            pass
        
        self.pycinfos: List[PycInfo] = self.bv.session_data['pycinfos']
        self.opcodes = self.bv.session_data['opcodes']


    def disasm(self, data: bytes, addr: int) -> InstructionInfo:
        self.setup()

        i_info = InstructionInfo()
        i_info.length = 2

        if data[0] in set(self.opcodes.hasjabs + self.opcodes.hasjrel + [self.opcodes.RETURN_VALUE, ]):
            i_info = self.add_jump_branchs(i_info, data, addr)

        return i_info


    def add_jump_branchs(self, i_info: InstructionInfo, data: bytes, addr: int) -> InstructionInfo:
        opcode = data[0]
        base = self._base_of(addr) # we need to add the "base_address" of the function for absolutes jumps
        next_i = addr + self.jump_instruction_length

        if self.opcodes.opname[opcode] == 'JUMP_ABSOLUTE':
            i_info.add_branch(BranchType.UnconditionalBranch, target=data[1] + base)

        elif self.opcodes.opname[opcode] in ('POP_JUMP_IF_FALSE', 'JUMP_IF_FALSE_OR_POP'):
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=data[1] + base)

        elif self.opcodes.opname[opcode] in ('POP_JUMP_IF_TRUE', 'JUMP_IF_TRUE_OR_POP'):
            i_info.add_branch(BranchType.TrueBranch, target=data[1] + base)
            i_info.add_branch(BranchType.FalseBranch, target=next_i)
        
        elif self.opcodes.opname[opcode] == 'JUMP_FORWARD':
            i_info.add_branch(BranchType.UnconditionalBranch, target=next_i + data[1])
        
        elif self.opcodes.opname[opcode] == 'FOR_ITER':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, next_i + data[1])
        
        elif self.opcodes.opname[opcode] == 'SETUP_LOOP':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + data[1])

        elif self.opcodes.opname[opcode] in ('SETUP_WITH', 'SETUP_ASYNC_WITH'):
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + data[1])

        elif self.opcodes.opname[opcode] == 'SETUP_FINALLY':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + data[1])
        
        elif self.opcodes.opname[opcode] == 'CALL_FINALLY': # 3.8 specific
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + data[1])

        elif self.opcodes.opname[opcode] == 'SETUP_EXCEPT':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + data[1])

        elif self.opcodes.opname[opcode] == 'RETURN_VALUE':
            i_info.add_branch(BranchType.FunctionReturn)


        return i_info

    ### Instruction text

    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int]:
        instruction = self.disasm(data, addr)
        if instruction is None:
            return None

        tokens = []
        opcode = data[0]
        opname = self.opcodes.opname[opcode]
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.InstructionToken, opname)
        )

        # handle jumps
        if opcode in set(self.opcodes.hasjabs + self.opcodes.hasjrel):
            tokens.append(
                self.add_jump(data, addr)
            )

        if opcode < self.opcodes.HAVE_ARGUMENT:
            return tokens, instruction.length

        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TextToken, " ")
        )

        if opcode in self.opcodes.hasname:
            value = self.get_name_at(data[1], addr)
            if (opname == 'LOAD_NAME' or opname == 'LOAD_GLOBAL') and len(self.bv.get_functions_by_name(value)) != 0:
                self.loaded_function_names.append(value)
            elif opname == 'LOAD_METHOD':
                self.loaded_function_names.append(value)

            tokens.append(
                InstructionTextToken(InstructionTextTokenType.ArgumentNameToken, f'"{value[:50]}"')
            )
        
        elif opcode in self.opcodes.hasconst:
            tokens.extend(
                self.add_const(data, addr)
            )

        elif opcode in [self.opcodes.LOAD_FAST, self.opcodes.STORE_FAST, self.opcodes.DELETE_FAST]:
            try:
                value = self.get_varname_at(data[1], addr)
            except IndexError:
                x = self._index_of(addr) + 1
                value = self.pycinfos[x].co.co_varnames[data[1]]

            tokens.append(
                InstructionTextToken(InstructionTextTokenType.CharacterConstantToken, value)
            )

        elif opcode == self.opcodes.COMPARE_OP:
            op = self.opcodes.cmp_op[data[1]]
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.KeywordToken, ' ' + op)
            )

        if opname in ('CALL_FUNCTION', 'CALL_FUNCTION_EX', 'CALL_FUNCTION_KW', 'CALL_METHOD') and self.loaded_function_names:
            try:
                tokens.append(
                    InstructionTextToken(InstructionTextTokenType.DataSymbolToken, self.loaded_function_names[-1],
                        self.bv.get_functions_by_name(self.loaded_function_names[-1])[0].lowest_address)
                )
                self.loaded_function_names.pop()
            except IndexError: # no such function name
                pass

        return tokens, instruction.length


    def add_jump(self, data: bytes, addr: int) -> InstructionTextToken:
        opname = self.opcodes.opname[data[0]]
        x = data[1]
        next_i = addr + self.jump_instruction_length

        if opname == 'JUMP_ABSOLUTE':
            return InstructionTextToken(
                InstructionTextTokenType.AddressDisplayToken, f' {hex(x)}', x
            )
        elif opname in ('POP_JUMP_IF_FALSE', 'JUMP_IF_FALSE_OR_POP', 'POP_JUMP_IF_TRUE', 'JUMP_IF_TRUE_OR_POP'):
            return InstructionTextToken(
                InstructionTextTokenType.AddressDisplayToken, f' {hex(x)}', x
            )

        # Relative jumps
        elif data[0] in self.opcodes.hasjrel:
            return InstructionTextToken(
                InstructionTextTokenType.AddressDisplayToken, f' {hex(x + next_i)}', x + next_i
            )

        raise Exception(f'Not handled OPCODE : {opname}')


    def add_const(self, data: bytes, addr: int) -> Tuple[InstructionTextToken]:
        value = self.get_const_at(data[1], addr)

        if isinstance(value, int):
            return InstructionTextToken(
                InstructionTextTokenType.IntegerToken, f'{value}'[:50]
            ),
        elif isinstance(value, float):
            return InstructionTextToken(
                InstructionTextTokenType.FloatingPointToken, f'{value}'[:50]
            ),
        elif isinstance(value, str):
            return InstructionTextToken(
                InstructionTextTokenType.CharacterConstantToken, f'"{value[:50]}"'
            ),
        elif isinstance(value, bytes):
            return InstructionTextToken(
                InstructionTextTokenType.CharacterConstantToken, f'{value}'[:50]
            ),
        elif isinstance(value, tuple) or isinstance(value, list):
            return InstructionTextToken(
                InstructionTextTokenType.StringToken, f'{value}'[:50]
            ),
        elif value is None:
            return InstructionTextToken(
                InstructionTextTokenType.DataSymbolToken, 'None'
            ),
        
        return InstructionTextToken(
            InstructionTextTokenType.DataSymbolToken, f'{str(type(value))[:50]}' 
        ), InstructionTextToken(
            InstructionTextTokenType.TextToken, ' '
        ), InstructionTextToken(
            InstructionTextTokenType.IntegerToken, f'{{{data[1]}}}'
        )

    """
    Recovers co.co_names[i] according to the function in which the opcode is
    """
    def get_name_at(self, index: int, addr: int) -> str:
        x = self._index_of(addr)
        return self.pycinfos[x].co.co_names[index]
    
    """
    Recovers co.co_consts[i] according to the function in which the opcode is
    """
    def get_const_at(self, index: int, addr: int) -> object:
        x = self._index_of(addr)
        return self.pycinfos[x].co.co_consts[index]

    """
    Recovers co.co_consts[i] according to the function in which the opcode is
    """
    def get_varname_at(self, index: int, addr: int) -> str:
        x = self._index_of(addr)
        return self.pycinfos[x].co.co_varnames[index]


    def _index_of(self, addr: int) -> int:
        for i, f in enumerate(self.bv.functions):
            for addr_range in f.address_ranges:
                if addr in addr_range:
                    return i
        raise Exception('no no no')

    def _base_of(self, addr: int) -> int:
        previous = 0
        base = 0
        for f in self.bv.session_data['functions']:
            base = f[1]
            if addr < base:
                return previous
            previous = base
        return base


    def get_nop(self) -> bytes:
        self.setup()

        return bytes([self.opcodes.NOP, 0])


    def invert_branch(self, data: bytes, addr: int) -> bytes:
        opname = self.opcodes.opname[data[0]]

        if opname in ('JUMP_ABSOLUTE', 'JUMP_FORWARD'):
            return self.get_nop()

        elif opname == 'POP_JUMP_IF_FALSE':
            return bytes([self.opcodes.opmap['POP_JUMP_IF_TRUE'], data[1]])

        elif opname == 'POP_JUMP_IF_TRUE':
            return bytes([self.opcodes.opmap['POP_JUMP_IF_FALSE'], data[1]])

        elif opname == 'JUMP_IF_FALSE_OR_POP':
            return bytes([self.opcodes.opmap['JUMP_IF_TRUE_OR_POP'], data[1]])

        elif opname == 'JUMP_IF_TRUE_OR_POP':
            return bytes([self.opcodes.opmap['JUMP_IF_FALSE_OR_POP'], data[1]])

        return None

"""
The Disassembler for python bytecode version <= 3.5
"""
class Disassembler35(Disassembler):
    def __init__(self):
        super().__init__()
        self.jump_instruction_length = 3

    def disasm(self, data: bytes, addr: int) -> InstructionInfo:
        self.setup()

        i_info = InstructionInfo()
        i_info.length = 1

        if data[0] in set(self.opcodes.hasjabs + self.opcodes.hasjrel):
            i_info = self.add_jump_branchs(i_info, data, addr)
            i_info.length = self.jump_instruction_length
        
        elif data[0] == self.opcodes.RETURN_VALUE:
            i_info = self.add_jump_branchs(i_info, data, addr)

        if data[0] >= self.opcodes.HAVE_ARGUMENT:
            i_info.length = 3

        return i_info