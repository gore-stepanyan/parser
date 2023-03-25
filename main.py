import pyshark
from packet import Packet
import socket
import time

def main():
    count = 0
    capture = pyshark.FileCapture(input_file='pcap_session.pcap', display_filter='', use_json=True, include_raw=True)
    for p in capture:
        packet = Packet()
        packet.read(p.get_raw_packet())
        count = count + 1
        print("\033c", end='')
        print(packet.fields)
        
main()