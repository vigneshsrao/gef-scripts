from ctypes import *

class test_struct(Structure):
    _fields_ = [
       ("field_0", c_ulong),
       ("field_8", c_int),
       ("field_C", c_short),
       ("field_E", c_char*30)
    ]
        