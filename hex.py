from struct import *
data = b'\x08\x00\x63\x64\x65'
print(unpack('! H 2s', data[:4]))
one, two = unpack('! H 2s', data[:4]) ## convert bytes to unsigned int
print(one)
print('0x%04x' % one)
print(hex(one)) ##convert int to string which is hexadecimal expression
print(type(hex(one))) ##convert int to string which is hexadecimal expression