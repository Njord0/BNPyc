from binaryninja import BinaryView, lowlevelil
from binaryninjaui import UIContext

from typing import Optional, List

from .pycview import PycInfo

class Lifter:
    def __init__(self):
        self.bv: BinaryView = None


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


    def get_opcodes(self) -> object:
        return self.bv.session_data['opcodes']


    def setup(self):
        while not self.set_bv():
            pass
        
        self.pycinfos: List[PycInfo] = self.bv.session_data['pycinfos']
        self.opcodes = self.get_opcodes()


    def lift(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        self.setup()

        opcode = data[0]
        opname = self.opcodes.opname[opcode]

        if opname == 'NOP':
            expr = il.nop()
        else:
            expr = il.unimplemented()
        
        il.append(expr)        
        
        return 2
