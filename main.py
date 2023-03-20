import pyshark
from packet import Packet
import socket
import time

def main():
    capture = pyshark.FileCapture(input_file='pcap_session.pcap', display_filter='', use_json=True, include_raw=True)
    for p in capture:
        packet = Packet()
        packet.read(p.get_raw_packet())
        print(packet.fields)
        
main()