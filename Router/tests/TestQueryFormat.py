from igmpv3.packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from igmpv3.packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from igmpv3.packet.PacketIGMPHeader import PacketIGMPHeader

packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "223.0.4.1")
source_1 = PacketIGMPMSourceAddress("192.3.34.1")
source_2 = PacketIGMPMSourceAddress("192.3.34.2")
packet.addSourceAddress(source_1)
packet.addSourceAddress(source_2)
print("/*                              */")
print("/* Created object: Packet Query */")
print("/*                              */")
print("RESV: {}".format(packet.getRESV()))
print("S: {}".format(packet.getS()))
print("QRV: {}".format(packet.getQRV()))
print("QQIC: {}".format(packet.getQQIC()))
print("Sources: ")
n =1
for i in packet.getSourceAddresses():
    print("{}: {}".format(n, i.getAddress()))
    n+=1
print("/*                              */")
print("/* Created same object in bytes */")
print("/*                              */")
pck_bytes = packet.bytes()
print(pck_bytes)
query = PacketIGMPv3HeaderQuery.parse_bytes(pck_bytes)
print("RESV: {}".format(query.getRESV()))
print("S: {}".format(query.getS()))
print("QRV: {}".format(query.getQRV()))
print("QQIC: {}".format(query.getQQIC()))
print("Sources: ")
n =1
for i in query.getSourceAddresses():
    print("{}: {}".format(n, i.getAddress()))
    n+=1
######################################################
######################################################
######################################################
print("/*                                */")
print("/* Created IGMP Header with Query */")
print("/*                                */")
# packet = IGMP Query
igmp_header = PacketIGMPHeader(packet)
print("IGMP Type: {}".format(igmp_header.getIgmpType()))
print("0x11 = {}".format(0x11))

print("/*                               */")
print("/* Created IGMP Header in bytes  */")
print("/*                               */")
igmp_header_bytes = igmp_header.bytes()
print(igmp_header_bytes)
print("Let's parse bytes . . .")
rcv_pkt = PacketIGMPHeader.parse_bytes(igmp_header_bytes)
print("RESV: {}".format(rcv_pkt.getPayload().getRESV()))
print("S: {}".format(rcv_pkt.getPayload().getS()))
print("QRV: {}".format(rcv_pkt.getPayload().getQRV()))
print("QQIC: {}".format(rcv_pkt.getPayload().getQQIC()))
print("Sources: ")
n =1
for i in rcv_pkt.getPayload().getSourceAddresses():
    print("{}: {}".format(n, i.getAddress()))
    n+=1