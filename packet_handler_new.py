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
        'state',
        'rtcp_flow_1',
        'rtcp_flow_2'
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

        self.rtcp_flow_1 = {
            'S_ij'    : [],
            'R_ij'    : [],
            'J'       : 0,
            'R_factor': float
        }

        self.rtcp_flow_2 = {
            'S_ij'    : [],
            'R_ij'    : [],
            'J'       : 0,
            'R_factor': float
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
        
    def print_metrics(self, rtcp_flow):
        d = self.data['RTD_average'] * 1000
        J = rtcp_flow['J'] * 1000
        R = rtcp_flow['R_factor']

        print(f'{d:.3f}', f'{J:.3f}', f'{R:.0f}')

    def compute_delay(self):
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
        # print(f'{TS_2:.3f} - {DLSR_2:.3f} - {DLSR_1:.3f} - {TS_1:.3f}')
        # print(f'{(RTD_current / 2):.3f}', f'{RTD_average:.3f}',  '\n')
        # print(RTD_average)

    def compute_jitter(self, rtcp_flow):
        S_i = float(rtcp_flow['S_ij'][0])
        S_j = float(rtcp_flow['S_ij'][1])
        R_i = float(rtcp_flow['R_ij'][0])
        R_j = float(rtcp_flow['R_ij'][1])
        J = rtcp_flow['J']
        D_ij = (R_j - R_i) - (S_j - S_i) / 8000
        J = J + (abs(D_ij) - J) / 16
        
        # print(self.data['S_ij'])
        # print(self.data['R_ij'])

        rtcp_flow.update(J = J)
        rtcp_flow['S_ij'].pop(0)
        rtcp_flow['R_ij'].pop(0)

    def compute_r_factor(self, rtcp_flow):
        #осталось узнать пэйлоад тайп и узнать коэффициенты по табличкам
        I_e = 0
        B_pl = 4.3
        P_pl = 0
        buffer = 20 # 20 мс например


        J = rtcp_flow['J'] * 1000 # ms
        d = self.data['RTD_average'] * 1000 # ms
        # в первоисточнике есть ограничения 175 - 400 мс
        I_d = 0.0267 * d if d <= 175 else 0.1194 * d - 15.876
        P_jitter = pow(1 + -0.1 * buffer / J, 20) / 2
        P_plef = P_pl + P_jitter - P_pl * P_jitter
        I_e_eff = I_e + (95 - I_e) * P_plef / (P_plef + B_pl)
        R_factor = 93.2 - I_d - I_e_eff

        rtcp_flow.update(R_factor = R_factor)
        
        #print(I_d, I_e_eff)
        self.print_metrics(rtcp_flow)
        #print('')
            
    def handle_sip_invite(self, packet):
        if 'sip_info' in packet.fields:
            if packet.fields['sip_info'] == 'INVITE':
                #print(self.state)
                self.session_info.update(call_id = packet.fields['call_id'])
                self.state = State.HANDLING_SIP_200_OK
                
    def handle_sip_200_ok(self, packet):
        if 'sip_info' in packet.fields:
            # баг 200 Ок ОК
            if packet.fields['sip_info'] == '200 OK' and self.session_info['call_id'] == packet.fields['call_id']:
                # print(self.state)
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
                # print(self.state)
                self.state = State.HANDLING_SECOND_PACKET
                
                # все пакеты RTCP1 образуют поток пакетов сендера rtcp_flow_1 для которых рассчитывается джиттер:
                S = packet.fields['ts_rtp']
                self.rtcp_flow_1['S_ij'].append(S)
                R = packet.fields['sniff_timestamp']
                self.rtcp_flow_1['R_ij'].append(R)
                if len(self.rtcp_flow_1['S_ij']) == 2 and len(self.rtcp_flow_1['R_ij']) == 2:
                    self.compute_jitter(self.rtcp_flow_1)
                    self.compute_r_factor(self.rtcp_flow_1)

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
                    # print(self.state)
                    self.state = State.HANDLING_THIRD_PACKET

                    # все пакеты RTCP2 образуют поток пакетов сендера rtcp_flow_2 для которых рассчитывается джиттер:
                    S = packet.fields['ts_rtp']
                    self.rtcp_flow_2['S_ij'].append(S)
                    R = packet.fields['sniff_timestamp']
                    self.rtcp_flow_2['R_ij'].append(R)
                    if len(self.rtcp_flow_2['S_ij']) == 2 and len(self.rtcp_flow_2['R_ij']) == 2:
                        self.compute_jitter(self.rtcp_flow_2)
                        self.compute_r_factor(self.rtcp_flow_2)

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

                    # print(self.state)
                    #self.state = State.HANDLING_FIRST_PACKET # можно убрать

                    self.compute_delay()
                    
                    # представим что RTCP3 это очередной RTCP1:
                    self.handle_first_packet(packet)

    def on_packet_arrive(self, packet):
        #print(self.state)
        self.fabric[self.state](packet)
        # try:
        #     self.fabric[self.state](packet)
        #     return('ok')
        # except:
        #     print('произошло экстренное откисание')