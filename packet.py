import struct
import re

info_invite_re = re.compile(r'(INVITE) sip:')
info_200_Ok_re =  re.compile(r'(200 Ok)')
cseq_method_re = re.compile(r'CSeq: \d+ (\w+)')
sip_re = re.compile(r'SIP\/2\.0')
rtp_port_re = re.compile(r'm=audio (\d+)')
rtcp_port_re = re.compile(r'a=rtcp:(\d+)')
call_id_re = re.compile(r'Call-ID: ([a-zA-Z0-9]+)')

class Packet(object):
    __slots__ = (
        'fields',
        'rtp_ports',
        'rtcp_ports'
    )

    def __init__(self):
        self.fields = {}
        self.rtp_ports = []
        self.rtcp_ports = []

    # хуман редибл мак AA:BB:CC:DD:EE:FF
    def get_hr_mac(self, bytes_mac):
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()

    # хуман редибл айпи 192.168.0.0
    def get_hr_ipv4(self, bytes_ipv4):
        return '.'.join(map(str, bytes_ipv4))

    # распаковка
    def read_eth_header(self, data):
        # читаем первые 6 + 6 + 2 = 14 байт, H - short uint - два байта
        eth_dst, eth_src, eth_type = struct.unpack('! 6s 6s H', data[:14])
        #всратое форматирование 0x 4 символва для 0 -> 0x0800
        return self.get_hr_mac(eth_dst), self.get_hr_mac(eth_src), '0x%04x' % eth_type, data[14:]

    def read_ipv4_header(self, data):
        #читаем с девятого байта тип пакета (1 байт)
        #все интересные пакеты имеют 20 байт в заголовке, 2x - пропуск два байта чексума (ненужен)
        #по четыре байта на ip адреса
        ip_proto, ip_src, ip_dst = struct.unpack('! 1b 2x 4s 4s', data[9:20])
        return str(ip_proto), self.get_hr_ipv4(ip_src), self.get_hr_ipv4(ip_dst), data[20:]

    def read_udp_header(self, data):
        # по два байта на порты, остальное не нужно
        src_port, dst_port = struct.unpack('! H H 4x', data[:8])
        return str(src_port), str(dst_port), data[8:]
    
    def read_tcp_header(self, data):
        # по два байта на порты, полбайта на длину заголовка (для нагрузки)
        src_port, dst_port, hdr_len_reserved = struct.unpack('! H H 8x 1s', data[:13])
        hdr_len = int(hdr_len_reserved.hex()[0]) * 4
        return str(src_port), str(dst_port), data[hdr_len:]
      
    def parse_sip(self, data):
        if info_invite_re.search(data):
            sip_info = info_invite_re.findall(data)[0]
        elif info_200_Ok_re.search(data):
            sip_info = info_200_Ok_re.findall(data)[0]
        else:
            sip_info = ''

        if cseq_method_re.search(data):
            cseq_method = cseq_method_re.findall(data)[0]
        else:
            cseq_method = ''

        if call_id_re.search(data):
            call_id = call_id_re.findall(data)[0]
        else:
            call_id = ''

        if rtp_port_re.search(data):
            rtp_port = rtp_port_re.findall(data)[0]
        else:
            rtp_port = ''

        if rtcp_port_re.search(data):
            rtcp_port = rtcp_port_re.findall(data)[0]
        elif rtp_port:
            rtcp_port = str(int(rtp_port) + 1)
        else:
            rtcp_port = ''
        
        return sip_info, cseq_method, call_id, rtp_port, rtcp_port

    # по четыре байта на таймштампы и дилэй
    def read_rtcp_packet(self, data):
        ts_msw, ts_lsw, dlsr = struct.unpack('! 8x I I 32x I', data[:52])
        return ts_msw, ts_lsw, dlsr

    def read(self, data):
        self.fields.clear() # обновим поля

        eth_dst, eth_src, eth_type, eth_payload = self.read_eth_header(data)
        if eth_type != '0x0800': #только IPv4 EtherTypes
            return
        
        self.fields.update(eth_dst = eth_dst)
        self.fields.update(eth_src = eth_src)
        self.fields.update(eth_type = eth_type)
                
        ip_proto, ip_src, ip_dst, ip_payload = self.read_ipv4_header(eth_payload)
        if ip_proto != '17' and ip_proto != '6' : #только UDP и TCP сегменты
            return
        
        self.fields.update(ip_proto = ip_proto)
        self.fields.update(ip_src = ip_src)
        self.fields.update(ip_dst = ip_dst)

        if ip_proto == '17':    
            src_port, dst_port, payload = self.read_udp_header(ip_payload)
        else:
            src_port, dst_port, payload = self.read_tcp_header(ip_payload)
        
        self.fields.update(src_port = src_port)
        self.fields.update(dst_port = dst_port)
        
        payload_string = payload.decode('utf-8', 'replace')
        if sip_re.search(payload_string):
            sip_info, cseq_method, call_id,  rtp_port, rtcp_port = self.parse_sip(payload_string)
            self.fields.update(app_proto = 'sip')
            self.fields.update(sip_info = sip_info)
            self.fields.update(cseq_method = cseq_method)
            self.fields.update(call_id = call_id)
            self.fields.update(rtp_port = rtp_port)
            self.fields.update(rtcp_port = rtcp_port)

            # запомним ртп/ртсп порты чтобы парсить соответствующие пакеты
            if rtp_port and rtp_port not in self.rtp_ports:
                self.rtp_ports.append(rtp_port)
            if rtcp_port and rtcp_port not in self.rtcp_ports:
                self.rtcp_ports.append(rtcp_port)

        # нужны ртсп пакеты не короче 44 байт
        if (src_port in self.rtcp_ports or dst_port in self.rtcp_ports) and len(payload) >= 52:
            ts_msw, ts_lsw, dlsr = self.read_rtcp_packet(payload)
            self.fields.update(ts_msw = ts_msw)
            self.fields.update(ts_lsw = ts_lsw)
            self.fields.update(dlsr = dlsr)
