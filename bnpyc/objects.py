from binaryninja import BinaryView, Architecture, SegmentFlag, SectionSemantics, StructureBuilder, Type, DataRenderer, InstructionTextToken, InstructionTextTokenType, DisassemblyTextLine, Platform, log_info

from enum import IntEnum

class ObjectKind(IntEnum):
    STRING = 0
    INTEGER = 1
    FLOAT = 2
    NONE = 3
    ANY = 100

class ObjectRenderer(DataRenderer):
    def perform_is_valid_for_data(self, ctxt, view: BinaryView, addr: int, type, context):
        try:
            var = view.get_data_var_at(addr)
            return var.name == 'PythonObject'
        except:
            return False

    def perform_get_lines_for_data(self, ctxt, view: BinaryView, addr: int, type, prefix, width, context):
        tokens = []
        var = view.get_data_var_at(addr)

        tokens.append(
            InstructionTextToken(InstructionTextTokenType.StringToken, 'object ')
        )

        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TypeNameToken, var.value['name'] + b' ')
        )
        
        kind = var.value['kind']
        value = var.value['value'].replace(b'\x00', b'')

        instruction = None

        if kind == ObjectKind.STRING:
            instruction = InstructionTextToken(InstructionTextTokenType.StringToken, value)
        elif kind == ObjectKind.INTEGER:
            instruction = InstructionTextToken(InstructionTextTokenType.IntegerToken, value)
        elif kind == ObjectKind.FLOAT:
            instruction = InstructionTextToken(InstructionTextToken.FloatingPointToken, value)
        elif kind == ObjectKind.NONE:
            instruction = InstructionTextToken(InstructionTextTokenType.DataSymbolToken, 'None')
        else:
            instruction = InstructionTextToken(InstructionTextTokenType.CharacterConstantToken, value)
            
        tokens.append(instruction)

        return [DisassemblyTextLine(tokens, addr)]

ObjectRenderer().register_type_specific()