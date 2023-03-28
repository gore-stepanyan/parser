import socket
from packet import Packet
from packet_handler_new import PacketHandler

def main():
    packetHandler = PacketHandler()
    packet = Packet()
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = connection.recvfrom(65536)
        packet.read(raw_data)
        packetHandler.on_packet_arrive(packet)

main()