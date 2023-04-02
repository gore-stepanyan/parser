from struct import *
from ctypes import c_uint8
data = b'\x80\x00\x63\x64\x65'
marker_pt = b'\x87\x63'

pt, two = unpack('! 1B 1s', marker_pt[:2])

binary_mask = 0b01111111 ## Отбросить первый бит слева

print(bin(pt))
print(pt)
print(bin(pt & binary_mask))
print(pt & binary_mask)
