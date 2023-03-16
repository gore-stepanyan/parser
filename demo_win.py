import socket
import struct
import textwrap

# хуман редибл мак AA:BB:CC:DD:EE:FF
def get_hr_mac(bytes_mac):
    bytes_str = map('{:02x}'.format, bytes_mac)
    return ''.join(bytes_str).upper()
    
# распакоука
def eth_frame(data):
    # читаем первые 6 + 6 + 2 = 14 байт
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # htons нужен для учёта big- или little-endian форматов
    return get_hr_mac(dest_mac), get_hr_mac(src_mac), socket.htons(proto), data[14:]

def main():
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    while True:
        data = s.recvfrom(1024)
        print(data)

    HOST = socket.gethostbyname(socket.gethostname())    
    connection = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP) 
    connection.bind((HOST, 0))
    connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        raw_data, addr = connection.recvfrom(65536)
        print('here!')
        dest_mac, src_mac, proto, data = eth_frame(raw_data)
        print('\nEthernet frame:')
        print(f'Dest: {dest_mac}, Src: {src_mac}, Proto: {proto}')

main()