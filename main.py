import pyshark
from packet import Packet
from packet_handler_rtp import PacketHandler
import time

def main():
    packetHandler = PacketHandler()
    packet = Packet()
    capture = pyshark.FileCapture(input_file='long.pcap', display_filter='', use_json=True, include_raw=True)
    for p in capture:
        packet.read(p.get_raw_packet())
        packet.fields.update(sniff_timestamp = p.sniff_timestamp)
        packetHandler.on_packet_arrive(packet)
        #print("\033c", end='')
        #print(packet.fields)
        #input()
        
main()