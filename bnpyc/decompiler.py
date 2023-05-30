from binaryninja import BinaryView
from binaryninjaui import WidgetPane


from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QTextEdit, QVBoxLayout, QWidget, QComboBox
from PySide6.QtGui import QColor, QPalette

from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from pygments import highlight

from typing import Optional

import subprocess
import shutil


class CodeDisplay(QTextEdit):
    def __init__(self, text: str, parent: QWidget):
        text = CodeDisplay.parse_code(text)
        super().__init__(text, parent=parent)
        self.setReadOnly(True)
        self.resize(self.sizeHint())
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.setAutoFillBackground(True)
        
        palette = self.palette()
        palette.setColor(QPalette.Base, QColor.fromString('#272822')) # monokai background color
        self.setPalette(palette)

    def set_text(self, text: str):
        self.setText(CodeDisplay.parse_code(text))

    @staticmethod
    def parse_code(text: str) -> str:
        return highlight(text, PythonLexer(), HtmlFormatter(style='monokai', full=True, noclasses=True))


class DecompilerWidget(QWidget):
    def __init__(self, bv: BinaryView):
        QWidget.__init__(self)

        self.bv = bv

        self.create_top_layout()
        self.create_code_layout()

        layout = QVBoxLayout()
        layout.addLayout(self.top_layout)
        layout.addWidget(self.code_layout)
        layout.setAlignment(Qt.AlignLeft)
        
        self.setLayout(layout)

    def create_top_layout(self):
        """Create the top layout"""
        self.top_layout = QHBoxLayout()
        self.top_layout.addWidget(QLabel('Decompiler : '))
        self.create_combo_box()
        self.top_layout.addWidget(self.select_decompiler)

    def create_combo_box(self):
        """Create combo box"""
        self.select_decompiler = QComboBox()

        if shutil.which('pycdc'):
            self.select_decompiler.addItem('pycdc')
        
        if shutil.which('decompyle3'):
            self.select_decompiler.addItem('decompyle3')
        
        if shutil.which('uncompyle6'):
            self.select_decompiler.addItem('uncompyle6')

        self.select_decompiler.currentIndexChanged.connect(self.update_code)

    def create_code_layout(self):
        """Create the code layout with the current choosen decompiler"""
        self.code_layout = CodeDisplay('', self)
        self.update_code()

    def update_code(self):
        """Called the decompiler is changed"""
        code = self.get_code()
        if not code:
            code = '# An error occured during decompilation'

        self.code_layout.set_text(code)

    def get_code(self) -> Optional[str]:
        """try to decompile the pyc file """
        decompiler = self.select_decompiler.currentText()
        
        proc = subprocess.Popen([decompiler, self.bv.session_data['filename']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.wait() != 0:
            return None

        return proc.stdout.read().decode()


    @staticmethod
    def create_widget(context):
        """Open the widget"""
        if context.context and context.binaryView and context.binaryView.session_data.get('pycinfos'):
            widget = DecompilerWidget(context.binaryView)
            pane = WidgetPane(widget, 'BNPyc decompiler')
            context.context.openPane(pane)

    @staticmethod
    def can_create_widget(context):
        """Check if we can open the widget"""
        return context.context and context.binaryView and context.binaryView.session_data.get('pycinfos')
