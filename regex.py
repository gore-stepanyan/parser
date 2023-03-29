import re

s1 = 'INVITE sip:Nokia@192.168.43.58 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.43.236:5060;branch=z9hG4bK.bwnakQ5Yt;rport\r\nFrom: "Andrei" <sip:Andrei@192.168.43.236>;tag=IFiB4IJoN\r\nTo: sip:Nokia@192.168.43.58\r\nCSeq: 20 INVITE\r\nCall-ID: xGYHcL0tNy\r\nMax-Forwards: 70\r\nSupported: replaces, outbound, gruu\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\nContent-Type: application/sdp\r\nContent-Length: 234\r\nContact: <sip:192.168.43.236;transport=udp>;+sip.instance="<urn:uuid:84ba50de-f75c-0082-98e3-d5d1ed5ab9aa>"\r\nUser-Agent: Linphone Desktop/4.4.1 (BGEAM-2000) Windows 10 Version 2009, Qt 5.15.2 LinphoneCore/5.1.19-1-g6cdd0918e\r\n\r\nv=0\r\no=Andrei 1663 1408 IN IP4 192.168.43.236\r\ns=Talk\r\nc=IN IP4 192.168.43.236\r\nt=0 0\r\na=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics\r\nm=audio 7078 RTP/AVP 0\r\na=rtcp-fb:* trr-int 5000\r\na=rtcp-fb:* ccm tmmbr\r\n'
s2 = 'SIP/2.0 200 Ok\r\nVia: SIP/2.0/UDP 192.168.43.236:5060;branch=z9hG4bK.bwnakQ5Yt;rport\r\nFrom: "Andrei" <sip:Andrei@192.168.43.236>;tag=IFiB4IJoN\r\nTo: <sip:Nokia@192.168.43.58>;tag=NbkRlHC\r\nCall-ID: xGYHcL0tNy\r\nCSeq: 20 INVITE\r\nUser-Agent: LinphoneAndroid/5.0.7 (Nokia 6.1) LinphoneSDK/5.2.27 (tags/5.2.27^0)\r\nSupported: replaces, outbound, gruu, path, record-aware\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\nContact: <sip:Nokia@192.168.43.58;pn-prid=f1EwemxKT-CA3J6IQ98pRT:APA91bGdiWg1GEdylDdxDVHweLT7qgnMicOEGtuOrKbNLlfY7LxQ57Wk2j612UXSBBYK8QSCpvqnwu2qxBUkPjhFAI96inCzJwVnlYYqEKpSjltlOTDwa46fcf8lKwymrIWdyPQKUR02;pn-provider=fcm;pn-param=929724111839;pn-silent=1;pn-timeout=0>;+org.linphone.specs="conference/1.0,ephemeral/1.1,groupchat/1.2,lime"\r\nContent-Type: application/sdp\r\nContent-Length: 246\r\n\r\nv=0\r\no=Nokia 3311 3516 IN IP4 192.168.43.58\r\ns=Talk\r\nc=IN IP4 192.168.43.58\r\nt=0 0\r\na=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics\r\nm=audio 41465 RTP/AVP 0\r\na=rtcp:41192\r\na=rtcp-fb:* trr-int 5000\r\na=rtcp-fb:* ccm tmmbr\r\n'
s3 = 'xyuTa'

# info_200_Ok_re =  re.compile(r'(200 Ok)')
# sip_re = re.compile(r'SIP\/2\.0')
# rtp_port_re = re.compile(r'm=audio (\d+)')
# rtcp_port_re = re.compile(r'a=rtcp:(\d+)')
call_id_re = re.compile(r'Call-ID: (.+?)\s')



# s = s2


# if info_200_Ok_re.search(s):
#     print('matched')
#     print(info_200_Ok_re.findall(s)[0])
# else:
#     print('not matched')

call_id = call_id_re.findall(s1)
print(call_id)