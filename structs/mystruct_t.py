from ctypes import *

class mystruct_t(Structure):
    _fields_ = [
       ("age", c_int),
       ("id", c_ulong)
    ]

