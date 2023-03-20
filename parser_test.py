import pyshark
from packet import Packet

in_mem_capture = pyshark.InMemCapture()

def main():
    count = 0
    capture = pyshark.FileCapture(input_file='pcap_session.pcap', display_filter='', use_json=True, include_raw=True)
    print('hello')
    for reference_packet in capture:
        packet = Packet()
        packet.read(reference_packet.get_raw_packet())
        reference = in_mem_capture.parse_packet(binary_packet = reference_packet.get_raw_packet())
        print('hmm...')
                
        if 'eth_src' in packet.fields:
            if (reference.eth.src.upper()) != packet.fields['eth_src']:
                print('eth src error')
                count = count + 1

        if 'eth_dst' in packet.fields:
            if reference.eth.dst.upper() != packet.fields['eth_dst']:
                print('eth dst error')
                count = count + 1

        if 'eth_type' in packet.fields:
            if reference.eth.type != packet.fields['eth_type']:
                print('eth type error')
                count = count + 1        
        
        if 'ip_src' in packet.fields:
            if reference.ip.src != packet.fields['ip_src']:
                print('ip src error')
                count = count + 1

        if 'ip_dst' in packet.fields:
            if reference.ip.dst != packet.fields['ip_dst']:
                print('ip dst error')
                count = count + 1 

        if 'ip_proto' in packet.fields:
            if reference.ip.proto != packet.fields['ip_proto']:
                print('ip proto error')
                count = count + 1     
    
        #print(count)    

main()
