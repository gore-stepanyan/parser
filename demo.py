from time import time
import socket
from packet import Packet
from packet_handler import PacketHandler, State


def sniff() -> Packet:
    packet = Packet()
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = connection.recvfrom(65536)
        packet.read(raw_data)
        packet.fields.update(sniff_timestamp = time())
        yield packet

def main():
    handlers = []
    handlers.append(PacketHandler())
    
    for packet in sniff():
        print("\033c", end='')       
        
        for handler in handlers:
            handler.on_packet_arrive(packet)
            if handler.state == State.HANDLING_RTP_FLOW:
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
    
main()