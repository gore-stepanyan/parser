from struct import *
data = b'\x80\x00\x63\x64\x65'
print(unpack('! 1s 1s', data[:2]))
one, two = unpack('! 1s 1s', data[:2]) ## convert bytes to unsigned int
print(one)
print(one.hex()[0])

