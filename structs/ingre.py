from ctypes import *

class ingre(Structure):
    _fields_ = [
       ("name", c_char * 32),
       ("price", c_int),
       ("qty", c_int)
    ]

