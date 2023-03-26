from packet_handler_dev import PacketHandler
import pyshark
import asyncio
from concurrent.futures import ThreadPoolExecutor
import nest_asyncio

nest_asyncio.apply()

pool = ThreadPoolExecutor()
loop = asyncio.get_event_loop()

capture = pyshark.FileCapture(input_file='session_from_ecss_linphone.pcap', display_filter="rtcp.pt==200 || sdp || rtp")
packet_handler = PacketHandler()

async def listen():
    for packet in capture:
        return packet

def handle(packet):
    return packet_handler.on_packet_arrive(packet)

async def runner():
    packet = await listen()
    result = await loop.run_in_executor(pool, handle, packet)
    #print(result, " <- result")
    loop.create_task(runner())

def main():
    loop.create_task(runner())
    loop.run_forever()

if __name__ == "__main__":
    main()