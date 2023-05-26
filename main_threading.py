import pyshark
from packet_parser import PacketParser
from packet_handler import PacketHandler, State, RTPFlow
from time import time, sleep
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
import concurrent.futures
from typing import List

handlers:List[PacketHandler] = []

def sniff():
    capture1 = pyshark.FileCapture(input_file='packet_loss.pcap', display_filter='', use_json=True, include_raw=True)
    capture2 = pyshark.FileCapture(input_file='short.pcap', display_filter='', use_json=True, include_raw=True)
    
    # for subcapture in zip(capture1, capture2):
    #     for packet in subcapture:
    #         #sleep(0.01)
    #         yield packet
    for packet in capture1:
        yield packet            

def push_stats():
    while True:
        sleep(0.5)
        for handler in handlers:
            if handler.state == State.HANDLING_RTP_FLOW:
                for rtp_flow in handler.rtp_flows:
                    # регистр метрик
                    registry = CollectorRegistry()

                    R_factor = Gauge('R_factor', 'computed according to e-model', registry=registry)
                    R_factor.set_to_current_time()
                    R_factor.set(rtp_flow.R_factor)

                    P_pl = Gauge('P_pl', 'packet loss in %', registry=registry)
                    P_pl.set_to_current_time()
                    P_pl.set(rtp_flow.P_pl)

                    loss = Gauge('loss', 'packet loss in total', registry=registry)
                    loss.set_to_current_time()
                    loss.set(rtp_flow.loss)

                    d = Gauge('d', 'delay in ms', registry=registry)
                    d.set_to_current_time()
                    d.set(rtp_flow.d)

                    J = Gauge('J', 'jitter in ms', registry=registry)
                    J.set_to_current_time()
                    J.set(rtp_flow.J) 

                    i = Gauge('i', 'total packets captured', registry=registry)
                    i.set_to_current_time()
                    i.set(rtp_flow.i)

                    push_to_gateway(
                        'localhost:9091', 
                        job=f"call-ID:{handler.session_info['call_id']}_{rtp_flow.ip_src}:{rtp_flow.src_port}->{rtp_flow.ip_dst}:{rtp_flow.dst_port}",
                        registry=registry
                    )

def print_stats():
    while True:
        print("\033c", end='')
        sleep(0.5)
        for handler in handlers:
            if handler.state == State.HANDLING_RTP_FLOW:
                handler.print_metrics()

def start():
    parser = PacketParser()
    handlers.append(PacketHandler())
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        executor.submit(print_stats)
        executor.submit(push_stats)
        for p in sniff():
            futures = []
            #start = time()
            parser.read(p.get_raw_packet())
            #print(time() - start, 'time to read')
            parser.fields.update(sniff_timestamp = (p.sniff_timestamp))         

            #sleep(0.01)
            for handler in handlers:
                #start = time()
                futures.append(executor.submit(handler.on_packet_arrive, parser.fields))
                #print(time() - start, 'time to handle')
            
            # синхронизация тредов
            for future in concurrent.futures.as_completed(futures):
                break
                            
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


def main():
    try:
        start()
    except KeyboardInterrupt:
        exit()
    except Exception:
        pass

main()