from ctypes import *

class food(Structure):
    _fields_ = [
       ("name", c_char*24),
       ("ingredeints", c_ulong*13),
       ("next_food_ptr", c_ulong)
    ]

