import pyshark
from packet import Packet
from packet_handler import PacketHandler, State
from time import time, sleep

handlers = []

def sniff():
    capture1 = pyshark.FileCapture(input_file='packet_loss.pcap', display_filter='', use_json=True, include_raw=True)
    #capture2 = pyshark.FileCapture(input_file='short.pcap', display_filter='', use_json=True, include_raw=True)
    
    # for subcapture in zip(capture1, capture2):
    #     for packet in subcapture:
    #         #sleep(0.01)
    #         yield packet
    for packet in capture1:
        yield packet

def main():
    packet = Packet()
    handlers.append(PacketHandler())
    
    for p in sniff():
        print("\033c", end='')
        #start = time()
        packet.read(p.get_raw_packet())
        #print(time() - start, 'time to read')
        packet.fields.update(sniff_timestamp = (p.sniff_timestamp))         
        
        #sleep(0.01)
        for handler in handlers:
            #start = time()
            handler.on_packet_arrive(packet)
            #print(time() - start, 'time to handle')
            if handler.state == State.HANDLING_RTP_FLOW:
                handler.print_metrics()
                pass
        
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