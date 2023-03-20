import struct

class Packet(object):
    __slots__ = (
        "fields"
    )

    def __init__(self):
        self.fields = {}

    # хуман редибл мак AA:BB:CC:DD:EE:FF
    def get_hr_mac(self, bytes_mac):
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()

    def get_hr_ipv4(self, bytes_ipv4):
        return '.'.join(map(str, bytes_ipv4))

    # распакоука
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
    
    def read(self, data):
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
