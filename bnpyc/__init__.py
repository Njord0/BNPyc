from binaryninjaui import Menu, UIAction, UIActionHandler

from .python import *
from .pycview import PycView
from .decompiler import DecompilerWidget

Python.register()
Python35.register()
Python34.register()
Python33.register()
Python32.register()
Python31.register()
Python30.register()

PycView.register()

UIAction.registerAction('BNPyc decompiler')
UIActionHandler.globalActions().bindAction('BNPyc decompiler', UIAction(DecompilerWidget.create_widget, DecompilerWidget.can_create_widget))
Menu.mainMenu('Tools').addAction('BNPyc decompiler', 'BNPyc decompiler')