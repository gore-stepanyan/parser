from enum import Enum
import asyncio

class State(Enum):
        HANDLING_SDP_PACKET    = "handling_sdp_packet" 
        HANDLING_FIRST_PACKET  = "handling_first_packet"
        HANDLING_SECOND_PACKET = "handling_second_packet"
        HANDLING_THIRD_PACKET  = "handling_third_packet"

class PacketHandler(object):
    __slots__ = (
        "data", 
        "packet_cache",
        "fabric", 
        "state"
    )

    def __init__(self):
        self.data = {
            "TS_1"        : float,
            "TS_2"        : float,
            "DLSR_1"      : float,
            "DLSR_2"      : float,
            "RTD_array"   : [],
            "RTD_average" : float
        }

        self.fabric = {
            State.HANDLING_SDP_PACKET : self.handle_sdp_packet,
            State.HANDLING_FIRST_PACKET  : self.handle_first_packet, 
            State.HANDLING_SECOND_PACKET : self.handle_second_packet, 
            State.HANDLING_THIRD_PACKET  : self.handle_third_packet
        }

        self.packet_cache = {
            "ip_src"   : None,
            "port_src" : None
        }

        self.state = State.HANDLING_FIRST_PACKET

    def update_packet_cache(self, packet):
        self.packet_cache.update(ip_src = packet.ip.src)
        self.packet_cache.update(port_src = packet.udp.srcport)

    def get_rtcp(self, packet):
        field_names = packet.rtcp._all_fields
        field_values = packet.rtcp._all_fields.values()
        return dict(zip(field_names, field_values))
        
    def get_sip(self, packet):
        field_names = packet.sip._all_fields
        field_values = packet.sip._all_fields.values()
        return dict(zip(field_names, field_values))


    def is_reply(self, packet):
        current_packet_destination_ip  = packet.ip.dst
        current_packet_desination_port = packet.udp.dstport 
        previous_packet_source_ip      = self.packet_cache["ip_src"]
        previous_packet_source_port    = self.packet_cache["port_src"]

        return current_packet_destination_ip == previous_packet_source_ip and current_packet_desination_port == previous_packet_source_port

    def compute(self):
        TS_1 = self.data["TS_1"]
        TS_2 = self.data["TS_2"]
        DLSR_1 = self.data["DLSR_1"]
        DLSR_2 = self.data["DLSR_2"]

        RTD_current = (TS_2 -DLSR_2 - DLSR_1 - TS_1)
        RTD_array = self.data["RTD_array"]
        RTD_array.append(RTD_current / 2)
        RTD_average = sum(RTD_array) / len(RTD_array)
        self.data.update(RTD_average = RTD_average)

        print(self.data["TS_1"])
        print(self.data["TS_2"])
        print(self.data["DLSR_1"])
        print(self.data["DLSR_2"])
        print(RTD_current / 2)
        print(RTD_average)

    def handle_sdp_packet(self, packet):
        sip = self.get_sip(packet)
        if 'sip.Method' in sip:
            if sip['sip.Method'] == 'INVITE':
                pass

    def handle_first_packet(self, packet):
        self.update_packet_cache(packet)
        rtcp = self.get_rtcp(packet)

        #В первом фрейме таймпштамп находится на 9 и 10 индексах
        timestamp_msw = float(rtcp["rtcp.timestamp.ntp.msw"])
        timestamp_lsw = float(rtcp["rtcp.timestamp.ntp.lsw"]) / 4294967296 #2^32
        TS_1 = timestamp_msw + timestamp_lsw

        self.data.update(TS_1 = TS_1)
        self.state = State.HANDLING_SECOND_PACKET

    def handle_second_packet(self, packet):
        if self.is_reply(packet):
            self.update_packet_cache(packet)
            rtcp = self.get_rtcp(packet)

            print("внимание")
            print(packet.rtcp)
            DLSR_1 = float(rtcp["rtcp.ssrc.dlsr"]) / 65536 #2^16
            self.data.update(DLSR_1 = DLSR_1)
            self.state = State.HANDLING_THIRD_PACKET

    def handle_third_packet(self, packet):
        if self.is_reply(packet):
            rtcp = self.get_rtcp(packet)

            timestamp_msw = float(rtcp["rtcp.timestamp.ntp.msw"])
            timestamp_lsw = float(rtcp["rtcp.timestamp.ntp.lsw"]) / 4294967296 #2^32
            TS_2 = timestamp_msw + timestamp_lsw

            DLSR_2 = float(rtcp["rtcp.ssrc.dlsr"]) / 65536 #2^16

            self.data.update(TS_2 = TS_2)
            self.data.update(DLSR_2 = DLSR_2)

            self.state = State.HANDLING_FIRST_PACKET

            self.compute()  

    def on_packet_arrive(self, packet):
        try:
            #print(self.state)
            #self.print_rtcp(packet)
            #self.fabric[self.state](packet)
            print(packet.ip.src)
            return("ok")
        except:
            print("произошло экстренное откисание")