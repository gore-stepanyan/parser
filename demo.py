import socket
import struct
import textwrap

# хуман редибл мак AA:BB:CC:DD:EE:FF
def get_hr_mac(bytes_mac):
    bytes_str = map('{:02x}'.format, bytes_mac)
    return ':'.join(bytes_str).upper()
    
# распакоука
def eth_frame(data):
    # читаем первые 6 + 6 + 2 = 14 байт
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # htons нужен для учёта big- или little-endian форматов
    return get_hr_mac(dest_mac), get_hr_mac(src_mac), socket.htons(proto), data[14:]

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, proto, data = eth_frame(raw_data)
        print('\nEthernet frame:')
        print(f'Dest: {dest_mac}, Src: {src_mac}, Proto: {proto}')

main()