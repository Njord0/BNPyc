from binaryninja import BinaryView, Architecture, SegmentFlag, SectionSemantics, StructureBuilder, Type, DataRenderer, InstructionTextToken, InstructionTextTokenType, DisassemblyTextLine, Platform, log_info

from xdis import Code38, Code3, Code2, load_module
import xdis

from .objects import ObjectKind

from types import CodeType
from typing import NamedTuple, Tuple, List, Any
import tempfile
import struct

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

        original_filename = data.file.original_filename

        self._set_tmpfile()
        self.tmp = self._check_others_functions(self.pycinfo.co)
        self.code_size = self.tmpfile.tell()
        self.data_begin = self.code_size

        self.str_objects = []
        self._loads_objects(self.pycinfo.co)

        self.data = self._get_view()

        BinaryView.__init__(self, file_metadata = self.data.file, parent_view = self.data)
        self.platform = PycView.get_platform(self.pycinfo.version[:2])
        self.session_data['filename'] = original_filename

        log_info(f'[BNPyc] Using architecture {self.platform}')

    def _set_tmpfile(self) -> None:
        self.tmpfile = tempfile.NamedTemporaryFile('r+b', delete=False) # read write binary mode
        self.tmpfile.write(self.pycinfo.co.co_code)
        self.tmpfile.flush()
        self.funcs = [("", 0), ] # first function offset


    def _get_view(self) -> BinaryView:
        return BinaryView.open(self.tmpfile.name)


    def init(self) -> bool:
        self.session_data['pycinfos'] = [self.pycinfo, ]
        self.session_data['pycinfos'].extend(self.tmp)
        self.session_data['opcodes'] = xdis.get_opcode(self.pycinfo.version, self.pycinfo.is_pypy)
        self.session_data['functions'] = self.funcs
        self.session_data['extended_args'] = {}

        self.add_auto_segment(0, self.code_size, 0, self.code_size, SegmentFlag.SegmentContainsCode)
        self.add_auto_section("code", 0 , self.code_size, SectionSemantics.ReadOnlyCodeSectionSemantics)
        
        self.add_auto_segment(self.code_size,
            self.data.length - self.code_size,
            self.code_size,
            self.data.length - self.code_size, SegmentFlag.SegmentReadable
        )

        for name, offset in self.funcs:
            func = self.create_user_function(offset, self.platform)
            func.name = name if name else func.name

        ## Adding objects
        with StructureBuilder.builder(self, 'object') as object_info:
            object_info.packed = True
            object_info.append(Type.array(Type.char(), 50), 'name')
            object_info.append(Type.array(Type.char(), 50), 'value')
            object_info.append(Type.int(4), 'kind')
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
            self.data_begin += 104

        for c in code.co_consts:
            if self._is_code(c):
                recur.append(c)
                continue

            self.str_objects.append(self.data_begin)

            self.tmpfile.write(
                self._build_object(c)
            )
            self.data_begin += 104

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
                self.funcs.append((c.co_name, self.tmpfile.tell()))
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

        if isinstance(obj, str):
            return data.encode() + struct.pack('<i', ObjectKind.STRING)
        if isinstance(obj, int):
            return data.encode() + struct.pack('<i', ObjectKind.INTEGER)
        if isinstance(obj, float):
            return data.encode() + struct.pack('<i', ObjectKind.FLOAT)
        if obj is None:
            return data.encode() + struct.pack('<i', ObjectKind.NONE)

        return data.encode() + struct.pack('<i', ObjectKind.ANY)


    """
    Returns true if is code
    """
    def _is_code(self, c: object) -> bool:
        return isinstance(c, (Code38, Code3, Code2, CodeType))

    @staticmethod
    def get_platform(version: Tuple[int, int]) -> Platform:
        if version >= (3, 6):
            return Architecture['Python-bytecode'].standalone_platform
        if version == (3, 5):
            return Architecture['Python-bytecode35'].standalone_platform
        if version == (3, 4):
            return Architecture['Python-bytecode34'].standalone_platform
        if version == (3, 3):
            return Architecture['Python-bytecode33'].standalone_platform
        if version == (3, 2):
            return Architecture['Python-bytecode32'].standalone_platform
        if version == (3, 1):
            return Architecture['Python-bytecode31'].standalone_platform
        if version == (3, 0):
            return Architecture['Python-bytecode30'].standalone_platform

        raise Exception('Unsupported bytecode version !')

    def perform_get_address_size(self) -> int:
        return 8



