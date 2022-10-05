from binaryninja import BinaryView, Architecture, SegmentFlag, log_info

from xdis import Code38, Code3, load_module
from types import CodeType
import xdis

from typing import NamedTuple, Tuple, List
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

        self._set_tmp()
        self.tmp = self._check_others_functions(self.pycinfo.co)
        data = self._get_view()

        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['Python-bytecode'].standalone_platform
        self.data = data


    def _set_tmp(self) -> None:
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

        self.add_auto_segment(0, len(self.data), 0, len(self.data), SegmentFlag.SegmentContainsCode)

        self.tmpfile.seek(0)
        for offset in self.offsets:
            self.create_user_function(offset)
            
        return True

    """
    Recursively search for function in co.co_consts 
    """
    def _check_others_functions(self, code: object) -> List[PycInfo]:
        out = []
        for c in code.co_consts:
            if isinstance(c, Code38) or isinstance(c, Code3) or isinstance(c, CodeType):
                self.offsets.append(self.tmpfile.tell())
                self.tmpfile.write(c.co_code)
                self.tmpfile.flush()
                out.append(PycInfo(co = c))
                out.extend(self._check_others_functions(c))
        return out

