import pyshark
import socket

def get_packet_from_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    s.bind(('192.168.43.251', 51413))
    while True:
        packet = s.recvfrom(65535)
        print(packet)
        return


def get_packet():
    capture = pyshark.FileCapture(input_file='session_from_ecss_linphone.pcap', display_filter='', use_json=True, include_raw=True)
    for packet in capture:
        print(packet.get_raw_packet())
        return

get_packet_from_socket()