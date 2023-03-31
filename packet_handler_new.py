from packet import Packet
from enum import Enum

class State(Enum):
        HANDLING_SIP_INVITE    = 'handling_sip_invite'
        HANDLING_SIP_200_OK    = 'handling_sip_200_ok'
        HANDLING_FIRST_PACKET  = 'handling_first_packet'
        HANDLING_SECOND_PACKET = 'handling_second_packet'
        HANDLING_THIRD_PACKET  = 'handling_third_packet'
        HANDLING_SIP_BYE       = 'handling_sip_bye'

class PacketHandler(object):
    __slots__ = (
        'data', 
        'packet_cache',
        'session_info',
        'fabric', 
        'state'
    )

    def __init__(self):
        self.data = {
            'TS_1'        : float,
            'TS_2'        : float,
            'DLSR_1'      : float,
            'DLSR_2'      : float,
            'RTD_array'   : [],
            'RTD_average' : float
        }

        self.fabric = {
            State.HANDLING_SIP_INVITE    : self.handle_sip_invite,
            State.HANDLING_SIP_200_OK    : self.handle_sip_200_ok,
            State.HANDLING_FIRST_PACKET  : self.handle_first_packet, 
            State.HANDLING_SECOND_PACKET : self.handle_second_packet, 
            State.HANDLING_THIRD_PACKET  : self.handle_third_packet,
            State.HANDLING_SIP_BYE       : self.handle_sip_bye
        }

        self.session_info = {
            'rtp_ports'  : [],
            'rtcp_ports' : [],
            'call_id'    : None

        }
        self.packet_cache = {
            'ip_src'   : None,
            'src_port' : None
        }

        self.state = State.HANDLING_SIP_INVITE

    def update_packet_cache(self, packet):
        self.packet_cache.update(ip_src = packet.fields['ip_src'])
        self.packet_cache.update(src_port = packet.fields['src_port'])

    def is_reply(self, packet):
        current_packet_destination_ip  = packet.fields['ip_dst']
        current_packet_desination_port = packet.fields['dst_port']
        previous_packet_source_ip      = self.packet_cache['ip_src']
        previous_packet_source_port    = self.packet_cache['src_port']

        return current_packet_destination_ip == previous_packet_source_ip and current_packet_desination_port == previous_packet_source_port
    
    def is_session_end(self, packet):
        if 'sip_info' in packet.fields:
            return packet.fields['sip_info'] == 'BYE'

    def compute(self):
        TS_1 = self.data['TS_1']
        TS_2 = self.data['TS_2']
        DLSR_1 = self.data['DLSR_1']
        DLSR_2 = self.data['DLSR_2']

        RTD_current = (TS_2 - DLSR_2 - DLSR_1 - TS_1)
        RTD_array = self.data['RTD_array']
        RTD_array.append(RTD_current / 2)
        RTD_average = sum(RTD_array) / len(RTD_array)
        self.data.update(RTD_average = RTD_average)

        # print(self.data['TS_1'])
        # print(self.data['TS_2'])
        # print(self.data['DLSR_1'])
        # print(self.data['DLSR_2'])
        print(f'{TS_2:.3f} - {DLSR_2:.3f} - {DLSR_1:.3f} - {TS_1:.3f}')
        print(f'{(RTD_current / 2):.3f}', f'{RTD_average:.3f}',  '\n')
        #print(RTD_average)

    def handle_sip_invite(self, packet):
        if 'sip_info' in packet.fields:
            if packet.fields['sip_info'] == 'INVITE':
                print(self.state)
                self.session_info.update(call_id = packet.fields['call_id'])
                self.state = State.HANDLING_SIP_200_OK
                
    def handle_sip_200_ok(self, packet):
        if 'sip_info' in packet.fields:
            # баг 200 Ок ОК
            if packet.fields['sip_info'] == '200 OK' and self.session_info['call_id'] == packet.fields['call_id']:
                print(self.state)
                self.session_info.update(rtp_ports = packet.rtp_ports)
                self.session_info.update(rtcp_ports = packet.rtcp_ports)
                self.state = State.HANDLING_FIRST_PACKET

    def handle_sip_bye(self, packet):
        print('конец сессии')
        # по идее здесь надо отследить ещё 200 ок
        # и завершить тред
        pass

    def handle_first_packet(self, packet):
        if self.is_session_end(packet):
            print('конец сессии')
            self.state = State.HANDLING_SIP_INVITE
            #exit()

        if 'proto_info' in packet.fields:
            if packet.fields['proto_info'] == 'rtcp':
                self.update_packet_cache(packet)

                ts_msw = float(packet.fields['ts_msw'])
                ts_lsw = float(packet.fields['ts_lsw']) / 4294967296 #2^32
                TS_1 = ts_msw + ts_lsw

                self.data.update(TS_1 = TS_1)
                print(self.state)
                self.state = State.HANDLING_SECOND_PACKET

    def handle_second_packet(self, packet):
        if self.is_session_end(packet):
            print('конец сессии')
            self.state = State.HANDLING_SIP_INVITE
            #exit()

        if 'proto_info' in packet.fields:
            if packet.fields['proto_info'] == 'rtcp':
                if self.is_reply(packet):
                    self.update_packet_cache(packet)

                    DLSR_1 = float(packet.fields['dlsr']) / 65536 #2^16
                    self.data.update(DLSR_1 = DLSR_1)
                    print(self.state)
                    self.state = State.HANDLING_THIRD_PACKET

    def handle_third_packet(self, packet):
        if self.is_session_end(packet):
            print('конец сессии')
            self.state = State.HANDLING_SIP_INVITE
            #exit()

        if 'proto_info' in packet.fields:
            if packet.fields['proto_info'] == 'rtcp':
                if self.is_reply(packet):
                    ts_msw = float(packet.fields['ts_msw'])
                    ts_lsw = float(packet.fields['ts_lsw']) / 4294967296 #2^32
                    TS_2 = ts_msw + ts_lsw

                    DLSR_2 = float(packet.fields['dlsr']) / 65536 #2^16

                    self.data.update(TS_2 = TS_2)
                    self.data.update(DLSR_2 = DLSR_2)

                    print(self.state)
                    self.state = State.HANDLING_FIRST_PACKET

                    self.compute()

    def on_packet_arrive(self, packet):
        #print(self.state)
        self.fabric[self.state](packet)
        # try:
        #     self.fabric[self.state](packet)
        #     return('ok')
        # except:
        #     print('произошло экстренное откисание')