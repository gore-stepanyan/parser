import pyshark
import struct
import socket
import time

# хуман редибл мак AA:BB:CC:DD:EE:FF
def get_hr_mac(bytes_mac):
    bytes_str = map('{:02x}'.format, bytes_mac)
    return ':'.join(bytes_str).upper()

def get_hr_ipv4(bytes_ipv4):
    return '.'.join(map(str, bytes_ipv4))
    
# распакоука
def eth_frame(data):
    # читаем первые 6 + 6 + 2 = 14 байт
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # htons нужен для учёта big- или little-endian форматов
    return get_hr_mac(dest_mac), get_hr_mac(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_hl = data[0]
    version = version_hl >> 4
    header_length = (version_hl & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_hr_ipv4(src), get_hr_ipv4(dest), data[header_length:]

def main():
    capture = pyshark.FileCapture(input_file='newtrace.pcap', display_filter='', use_json=True, include_raw=True)
    for packet in capture:
        dest_mac, src_mac, proto, data = eth_frame(packet.get_raw_packet())
        print('\nEthernet frame:')
        print(f'Dest: {dest_mac}, Src: {src_mac}, Proto: {proto}')
        
        version, header_length, ttl, proto, src, dest, data = ipv4_packet(data)
        print('IP packet:')
        print(version, header_length, ttl, proto, src, dest)
        time.sleep(1)

main()