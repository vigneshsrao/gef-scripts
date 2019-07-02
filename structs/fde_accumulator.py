from ctypes import *

class fde_accumulator(Structure):
    _fields_ = [
       ("linear", c_ulong),
       ("erratic", c_ulong)
    ]
        