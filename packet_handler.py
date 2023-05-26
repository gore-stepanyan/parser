from packet_parser import PacketParser
from enum import Enum
from typing import List
import logging

#logging.basicConfig(filename='output.txt', level=logging.DEBUG, format='')

class RTPFlow(object):
    __slots__ = (
        'ip_src',
        'src_port',
        'ip_dst',
        'dst_port',
        'S_ij',
        'R_ij',
        'J',
        'd',
        'i',
        'loss',
        'P_pl',
        'prev_seq_num',
        'R_factor'
    )

    def __init__(self):
        self.ip_src = ''
        self.src_port = ''
        self.ip_dst = ''
        self.dst_port = ''
        self.S_ij = []
        self.R_ij = []
        self.J = 0
        self.d = 0
        self.i = 0
        self.loss = 0
        self.P_pl = 0.0
        self.prev_seq_num = 0
        self.R_factor = 0

class State(Enum):
        HANDLING_SIP_INVITE = 'handling_sip_invite'
        HANDLING_SIP_200_OK = 'handling_sip_200_ok'
        HANDLING_RTP_FLOW   = 'handling_rtp_flow'
        HANDLING_SIP_BYE    = 'handling_sip_bye'

class PacketHandler(object):
    __slots__ = (
        'session_info',
        'fabric', 
        'state',
        'rtp_flows',
        'sessions'
    )

    def __init__(self):
        self.fabric = {
            State.HANDLING_SIP_INVITE    : self.handle_sip_invite,
            State.HANDLING_SIP_200_OK    : self.handle_sip_200_ok,
            State.HANDLING_RTP_FLOW      : self.handle_rtp_flow, 
            State.HANDLING_SIP_BYE       : self.handle_sip_bye
        }

        self.session_info = {
            'rtp_ports'     : [],
            'rtcp_ports'    : [],
            'call_id'       : None
        }

        self.rtp_flows:List[RTPFlow] = []
        self.state = State.HANDLING_SIP_INVITE
    
    def is_session_end(self, packet):
        if 'sip_info' in packet:
            return packet['sip_info'] == 'BYE' and self.session_info['call_id'] == packet['call_id']
        
    def print_metrics(self):
        call_id = self.session_info['call_id']
        print('call:', call_id)
        for rtp_flow in self.rtp_flows:
            src_port = rtp_flow.src_port
            dst_port = rtp_flow.dst_port
            ip_src = rtp_flow.ip_src
            ip_dst = rtp_flow.ip_dst

            #if ip_src == '192.168.43.173':
            d = rtp_flow.d
            J = rtp_flow.J
            loss = rtp_flow.loss
            P_pl = rtp_flow.P_pl
            i = rtp_flow.i
            R = rtp_flow.R_factor
            print(
                '\t',
                f'{ip_src}:{src_port}', '->', 
                f'{ip_dst}:{dst_port}', 
                f'{d:.3f}', 
                f'{J:.3f}',
                f'{i}',
                f'{loss}',
                f'{P_pl:.2f}%',
                f'{R:.3f}'
            )
            #logging.info((ip_src, '->', ip_dst, f'{d:.3f}', f'{J:.3f}', f'{R:.3f}'))

    def compute_jitter(self, rtp_flow: RTPFlow, packet):
        S = packet['ts'] * 1000 # ms
        rtp_flow.S_ij.append(S)
        R = float(packet['sniff_timestamp']) * 1000 # ms
        rtp_flow.R_ij.append(R)
        
        if len(rtp_flow.S_ij) == 2 and len(rtp_flow.R_ij) == 2:
            S_i = rtp_flow.S_ij[0]
            S_j = rtp_flow.S_ij[1]
            R_i = rtp_flow.R_ij[0]
            R_j = rtp_flow.R_ij[1]
            J = rtp_flow.J
            d = rtp_flow.d
            i = rtp_flow.i
            
            D_ij = (R_j - R_i) - (S_j - S_i) / 8000
            J = J + (abs(D_ij) - J) / 16
            d = (d * i + J) / (i + 1)

            rtp_flow.J = J
            rtp_flow.d = d
            rtp_flow.i = i + 1
            rtp_flow.S_ij.pop(0)
            rtp_flow.R_ij.pop(0)

            loss = rtp_flow.loss
            loss = loss + packet['seq_num'] - rtp_flow.prev_seq_num - 1
            P_pl = loss / (i + 1) * 100
            rtp_flow.P_pl = P_pl
            rtp_flow.loss = loss

            self.compute_r_factor(rtp_flow)
        
        rtp_flow.prev_seq_num = packet['seq_num']

    def compute_r_factor(self, rtp_flow: RTPFlow):
        #осталось узнать пэйлоад тайп и узнать коэффициенты по табличкам
        I_e = 0
        B_pl = 4.3
        P_pl = rtp_flow.P_pl
        buffer = 20 # 20 мс например


        J = rtp_flow.J
        d = rtp_flow.d
        # в первоисточнике есть ограничения 175 - 400 мс
        I_d = 0.0267 * d if d <= 175 else 0.1194 * d - 15.876
        P_jitter = pow(1 + -0.1 * buffer / J, 20) / 2
        P_plef = P_pl + P_jitter - P_pl * P_jitter
        I_e_eff = I_e + (95 - I_e) * P_plef / (P_plef + B_pl)
        R_factor = 93.2 - I_d - I_e_eff

        rtp_flow.R_factor = R_factor
        
        
        #self.print_metrics()
        #print('')
            
    def handle_sip_invite(self, packet):
        if 'sip_info' in packet:
            if packet['sip_info'] == 'INVITE':
                #print(self.state)
                self.session_info.update(call_id    = packet['call_id'])
                
                rtpFlow = RTPFlow()
                rtpFlow.ip_src       = packet['ip_src']
                rtpFlow.ip_dst       = packet['ip_dst']
                rtpFlow.src_port     = packet['rtp_port']
                
                self.rtp_flows.append(rtpFlow)
                self.state = State.HANDLING_SIP_200_OK
                
    def handle_sip_200_ok(self, packet):
        if 'sip_info' in packet:
            # баг 200 Ок ОК
            if packet['sip_info'] == '200 OK' and self.session_info['call_id'] == packet['call_id']:
                # print(self.state)
                rtpFlow = RTPFlow()
                rtpFlow.ip_src       = packet['ip_src']
                rtpFlow.ip_dst       = packet['ip_dst']
                rtpFlow.src_port     = packet['rtp_port']
                rtpFlow.dst_port     = self.rtp_flows[0].src_port
                self.rtp_flows[0].dst_port = packet['rtp_port']

                self.rtp_flows.append(rtpFlow)
                self.state = State.HANDLING_RTP_FLOW

    def handle_sip_bye(self, packet):
        print('конец сессии')
        # по идее здесь надо отследить ещё 200 ок
        # и завершить тред
        pass

    def handle_rtp_flow(self, packet):
        if self.is_session_end(packet):
            print('конец сессии')
            self.state = State.HANDLING_SIP_INVITE
            return

        if 'proto_info' in packet:
            if packet['proto_info'] == 'rtp':
                if packet['ip_src'] == self.rtp_flows[0].ip_src and packet['src_port'] == self.rtp_flows[0].src_port:
                    self.compute_jitter(self.rtp_flows[0], packet)
                
                if packet['ip_src'] == self.rtp_flows[1].ip_src and packet['src_port'] == self.rtp_flows[1].src_port:
                    self.compute_jitter(self.rtp_flows[1], packet)

    def on_packet_arrive(self, packet):
        #print(self.state)
        self.fabric[self.state](packet)
        # try:
        #     self.fabric[self.state](packet)
        #     return('ok')
        # except:
        #     print('произошло экстренное откисание')