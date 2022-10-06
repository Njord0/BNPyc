from binaryninja import BinaryView, Architecture, SegmentFlag, SectionSemantics, StructureBuilder, Type, DataRenderer, InstructionTextToken, InstructionTextTokenType, TypeLibrary, DisassemblyTextLine, log_info

from xdis import Code38, Code3, load_module
from types import CodeType
import xdis

from typing import NamedTuple, Tuple, List, Any
import tempfile

class PycInfo(NamedTuple):
    version: Tuple[int, int, int] = None
    timestamp: int = None
    magic_int: int = None
    co: object = None
    is_pypy: bool = None
    source_size: int = None
    sip_hash: None = None


class PycView(BinaryView):
    name = 'PycView'
    long_name = name

    @classmethod
    def is_valid_for_data(self, data) -> bool:
        magic = data.read(0, 4)
        return magic in xdis.magics.magics.values()


    def __init__(self, data):
        self.pycinfo = PycInfo(*load_module(data.file.original_filename, {}))

        self._set_tmpfile()
        self.tmp = self._check_others_functions(self.pycinfo.co)
        self.code_size = self.tmpfile.tell()
        self.data_begin = self.code_size

        self.str_objects = []
        self._loads_objects(self.pycinfo.co)

        data = self._get_view()

        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['Python-bytecode'].standalone_platform
        self.data = data


    def _set_tmpfile(self) -> None:
        self.tmpfile = tempfile.NamedTemporaryFile('r+b') # read write binary mode
        self.tmpfile.write(self.pycinfo.co.co_code)
        self.tmpfile.flush()
        self.offsets = [0, ] # first function offset


    def _get_view(self) -> BinaryView:
        return BinaryView.open(self.tmpfile.name)


    def init(self) -> bool:
        self.session_data['pycinfos'] = [self.pycinfo, ]
        self.session_data['pycinfos'].extend(self.tmp)
        self.session_data['opcodes'] = xdis.get_opcode(self.pycinfo.version, self.pycinfo.is_pypy)

        self.add_auto_segment(0, self.code_size, 0, self.code_size, SegmentFlag.SegmentContainsCode)
        self.add_auto_section("code", 0 , self.code_size, SectionSemantics.ReadOnlyCodeSectionSemantics)
        
        self.add_auto_segment(self.code_size,
            len(self.data) - self.code_size,
            self.code_size,
            len(self.data) - self.code_size, SegmentFlag.SegmentReadable
        )

        self.tmpfile.seek(0)
        for offset in self.offsets:
            self.create_user_function(offset)

        ## Adding objects
        with StructureBuilder.builder(self, 'object') as object_info:
            object_info.packed = True
            object_info.append(Type.array(Type.char(), 50), 'name')
            object_info.append(Type.array(Type.char(), 50), 'value')
        ObjectType = Type.structure_type(object_info)

        for offset in self.str_objects:
            self.define_data_var(offset, ObjectType, 'PythonObject')

        return True

    """
    Recursively maps python object to memory
    """
    def _loads_objects(self, code: object):
        recur = []

        for name in code.co_names:
            self.str_objects.append(self.data_begin)

            self.tmpfile.write(
                self._build_object(name)
            )
            self.data_begin += 100

        for c in code.co_consts:
            if self._is_code(c):
                recur.append(c)

            self.str_objects.append(self.data_begin)

            self.tmpfile.write(
                self._build_object(c)
            )
            self.data_begin += 100

        for c in recur:
            self._loads_objects(c)

        self.tmpfile.flush()


    """
    Recursively search for function in co.co_consts 
    """
    def _check_others_functions(self, code: object) -> List[PycInfo]:
        out = []
        for c in code.co_consts:
            if self._is_code(c):
                self.offsets.append(self.tmpfile.tell())
                self.tmpfile.write(c.co_code)
                self.tmpfile.flush()
                out.append(PycInfo(co = c))
                out.extend(self._check_others_functions(c))
        return out


    def _build_object(self, obj: Any) -> bytes:
        data = b''

        data = str(type(obj))
        data = data.ljust(50, '\x00')
        if len(data) > 50:
            data = data[:48] + '\'>'

        str_value = str(obj).ljust(50, '\x00')
        if len(str_value) > 50:
            str_value = str_value[:47] + '...'

        data += str_value

        return data.encode()

    """
    Returns true if is code
    """
    def _is_code(self, c: object) -> bool:
        return isinstance(c, Code38) or isinstance(c, Code3) or isinstance(c, CodeType)


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
        value = var.value['value']
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.CharacterConstantToken, value)
        )

        return [DisassemblyTextLine(tokens, addr)]

ObjectRenderer().register_type_specific()