import pyshark
from packet import Packet
from packet_handler import PacketHandler, State
from time import time, sleep

handlers = []

def sniff():
    capture1 = pyshark.FileCapture(input_file='long.pcap', display_filter='', use_json=True, include_raw=True)
    capture2 = pyshark.FileCapture(input_file='short.pcap', display_filter='', use_json=True, include_raw=True)
    
    for subcapture in zip(capture1, capture2):
        for packet in subcapture:
            #sleep(0.01)
            yield packet

def main():
    busy_count = 0
    packet = Packet()
    handlers.append(PacketHandler())
    
    for p in sniff():
        print("\033c", end='')
        packet.read(p.get_raw_packet())
        packet.fields.update(sniff_timestamp = (p.sniff_timestamp))         
        
        #sleep(0.01)
        for handler in handlers:
            handler.on_packet_arrive(packet)
            handler.print_metrics()
        
        busy_count = 0
        for handler in handlers:
            if handler.state == State.HANDLING_SIP_200_OK or handler.state == State.HANDLING_RTP_FLOW:
                busy_count = busy_count + 1
        
        if len(handlers) == busy_count:
            handlers.append(PacketHandler())
        
        if len(handlers) - busy_count >= 2:
            for handler in handlers:
                if handler.state == State.HANDLING_SIP_INVITE:
                    handlers.remove(handler)
                    break

        



        #print(packet.fields)
        #input()

main()