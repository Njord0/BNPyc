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

        try:
            self.bv = cv.getCurrentBinaryView()
        except TypeError:
            return False

        if self.bv is None:
            return False

        return self.bv.session_data.get('pycinfos') != None # is it the right bv ?


    def setup(self):
        while not self.set_bv():
            pass
        
        self.pycinfos: List[PycInfo] = self.bv.session_data['pycinfos']
        self.opcodes = self.bv.session_data['opcodes']
        self.extended_args = self.bv.session_data['extended_args']


    def disasm(self, data: bytes, addr: int) -> InstructionInfo:
        self.setup()

        i_info = InstructionInfo()
        i_info.length = 2

        if data[0] in set(self.opcodes.hasjabs + self.opcodes.hasjrel + [self.opcodes.RETURN_VALUE, ]):
            i_info = self.add_jump_branchs(i_info, data, addr)

        elif self.opcodes.opname[data[0]] == 'EXTENDED_ARG':
            self.extended_args[addr] = data[1]

        return i_info


    def add_jump_branchs(self, i_info: InstructionInfo, data: bytes, addr: int) -> InstructionInfo:
        opcode = data[0]
        opname = self.opcodes.opname[opcode]
        base = self._base_of(addr) # we need to add the "base_address" of the function for absolutes jumps
        next_i = addr + self.jump_instruction_length

        value = self.get_value(data, addr)
        if self.has_extended_arg(addr) and self.pycinfos[0].version >= (3, 8, 0):
            value *= 2

        if self.add_jump_branchs_311(i_info, data, addr, value):
            return i_info # the instructions was already handled as a python 3.11 specific instruction

        elif opname == 'JUMP_ABSOLUTE':
            i_info.add_branch(BranchType.UnconditionalBranch, target=value + base)

        elif opname in ('POP_JUMP_IF_FALSE', 'JUMP_IF_FALSE_OR_POP'):
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=value + base)

        elif opname in ('POP_JUMP_IF_TRUE', 'JUMP_IF_TRUE_OR_POP'):
            i_info.add_branch(BranchType.TrueBranch, target=value + base)
            i_info.add_branch(BranchType.FalseBranch, target=next_i)

        elif opname == 'JUMP_IF_FALSE':
                i_info.add_branch(BranchType.TrueBranch, target=next_i)
                i_info.add_branch(BranchType.FalseBranch, target=value + next_i)

        elif opname == 'JUMP_IF_TRUE':
            i_info.add_branch(BranchType.TrueBranch, target=value + next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i)

        elif opname == 'JUMP_FORWARD':
            i_info.add_branch(BranchType.UnconditionalBranch, target=next_i + value)
        
        elif opname == 'FOR_ITER':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, next_i + value)
        
        elif opname == 'SETUP_LOOP':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + value)

        elif opname in ('SETUP_WITH', 'SETUP_ASYNC_WITH'):
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + value)

        elif opname == 'SETUP_FINALLY':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + value)
        
        elif opname == 'CALL_FINALLY': # 3.8 specific
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + value)

        elif opname == 'SETUP_EXCEPT':
            i_info.add_branch(BranchType.TrueBranch, target=next_i)
            i_info.add_branch(BranchType.FalseBranch, target=next_i + value)

        elif opname == 'RETURN_VALUE':
            i_info.add_branch(BranchType.FunctionReturn)


        return i_info
    
    def add_jump_branchs_311(self, i_info: InstructionInfo, data: bytes, addr: int, value: int) -> bool:
        """Handles python 3.11 specific opcodes
        Returns true if an instruction was handled, false otherwise 
        """
        opcode = data[0]
        opname = self.opcodes.opname[opcode]
        base = self._base_of(addr) # we need to add the "base_address" of the function for absolutes jumps
        next_i = addr + self.jump_instruction_length

        # see : https://docs.python.org/3/library/dis.html#opcode-JUMP_BACKWARD
        if opname in ('JUMP_BACKWARD', 'JUMP_BACKWARD_NO_INTERRUPT'):
            i_info.add_branch(BranchType.UnconditionalBranch, addr - value)
        
        if opname == 'POP_JUMP_FORWARD_IF_TRUE':
            i_info.add_branch(BranchType.TrueBranch, next_i + value)
            i_info.add_branch(BranchType.FalseBranch, next_i)
        elif opname == 'POP_JUMP_BACKWARD_IF_TRUE':
            i_info.add_branch(BranchType.TrueBranch, addr - value)
            i_info.add_branch(BranchType.FalseBranch, next_i)
        elif opname == 'POP_JUMP_FORWARD_IF_FALSE':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, addr + value)
        elif opname == 'POP_JUMP_BACKWARD_IF_FALSE':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, addr - value)
        elif opname == 'POP_JUMP_FORWARD_IF_NOT_NONE':
            i_info.add_branch(BranchType.TrueBranch, addr + value)
            i_info.add_branch(BranchType.FalseBranch, next_i)
        elif opname == 'POP_JUMP_BACKWARD_IF_NOT_NONE':
            i_info.add_branch(BranchType.TrueBranch, addr - value)
            i_info.add_branch(BranchType.FalseBranch, next_i)
        elif opname == 'POP_JUMP_FORWARD_IF_NONE':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, addr + value)
        elif opname == 'POP_JUMP_BACKWARD_IF_NONE':
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, addr - value)
        elif opname == 'JUMP_IF_TRUE_OR_POP': # changed in version 3.11
            i_info.add_branch(BranchType.TrueBranch, addr + value)
            i_info.add_branch(BranchType.FalseBranch, next_i)
        elif opname == 'JUMP_IF_FALSE_OR_POP': # changed in version 3.11
            i_info.add_branch(BranchType.TrueBranch, next_i)
            i_info.add_branch(BranchType.FalseBranch, addr + value)
        else:
            return False

        return True

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
            x = self.get_value(data, addr)
            value = self.get_name_at(x, addr)

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
            x = self.get_value(data, addr)
            try:
                value = self.get_varname_at(x, addr)
            except IndexError:
                x = self._index_of(addr) + 1
                value = self.pycinfos[x].co.co_varnames[x]

            tokens.append(
                InstructionTextToken(InstructionTextTokenType.CharacterConstantToken, value)
            )

        elif opcode == self.opcodes.COMPARE_OP:
            op = self.opcodes.cmp_op[data[1]]
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.KeywordToken, ' ' + op)
            )

        elif opcode == self.opcodes.EXTENDED_ARG:
            op = data[1]
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.IntegerToken, ' ' + hex(op))
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
        next_i = addr + self.jump_instruction_length

        x = self.get_value(data, addr)
        if self.has_extended_arg(addr) and self.pycinfos[0].version >= (3, 8, 0):
            x *= 2           

        if opname == 'JUMP_ABSOLUTE':
            return InstructionTextToken(
                InstructionTextTokenType.AddressDisplayToken, f' {hex(x)}', x
            )
        elif opname in ('POP_JUMP_IF_FALSE', 'JUMP_IF_FALSE_OR_POP', 'POP_JUMP_IF_TRUE', 'JUMP_IF_TRUE_OR_POP', 'JUMP_IF_TRUE', 'JUMP_IF_FALSE'):
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
        x = self.get_value(data, addr)

        value = self.get_const_at(x, addr)

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

    def has_extended_arg(self, addr: int) -> bool:
        """Check if the previous instruction has extended arg"""
        return (addr-2) in self.extended_args.keys()


    def get_extended_value(self, addr: int) -> int:
        """Get the EXTENDED_ARG value of instruction at addr"""
        if not self.has_extended_arg(addr):
            return 0

        return self.extended_args[addr - 2] + self.get_extended_value(addr - 2) << 8

    def get_value(self, data: bytes, addr: int) -> int:
        """Get the value + EXTENDED_ARG for the instruction at addr"""
        if len(data) < 2:
            return 0

        if not self.has_extended_arg(addr):
            return data[1]

        return data[1] + self.get_extended_value(addr)


    def get_name_at(self, index: int, addr: int) -> str:
        """Recovers co.co_names[i] according to the function in which the opcode is"""
        x = self._index_of(addr)
        if x == -1:
            return ''

        return self.pycinfos[x].co.co_names[index]
    

    def get_const_at(self, index: int, addr: int) -> object:
        """Recovers co.co_consts[i] according to the function in which the opcode is"""
        x = self._index_of(addr)
        if x == -1:
            return ''

        return self.pycinfos[x].co.co_consts[index]


    def get_varname_at(self, index: int, addr: int) -> str:
        """Recovers co.co_varnames[i] according to the function in which the opcode is"""
        x = self._index_of(addr)
        if x == -1:
            return ''

        return self.pycinfos[x].co.co_varnames[index]


    def _index_of(self, addr: int) -> int:
        for i, f in enumerate(self.bv.functions):
            for addr_range in f.address_ranges:
                if addr in addr_range:
                    return i
        return -1

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