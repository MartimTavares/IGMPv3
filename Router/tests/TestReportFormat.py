from igmpv3.packet.PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from igmpv3.packet.PacketGroupRecord import PacketGroupRecord
from igmpv3.packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from igmpv3.packet.PacketIGMPHeader import PacketIGMPHeader

packet = PacketIGMPv3HeaderReport(0)
rec_1 = PacketGroupRecord(4, "224.6.0.1")
rec_2 = PacketGroupRecord(1, "224.4.0.8")
rec_3 = PacketGroupRecord(3, "224.4.0.9")
src = PacketIGMPMSourceAddress("193.1.91.1")
src_2 = PacketIGMPMSourceAddress("193.1.91.2")
rec_1.addSourceAddress(src)
rec_1.addSourceAddress(src_2)
packet.addGroupRecord(rec_1)
packet.addGroupRecord(rec_2)
packet.addGroupRecord(rec_3)
print("/*                               */")
print("/* Created object: Packet Report */")
print("/*                               */")
print("Group Records: ")
n =1
for i in packet.group_records:
    print("Type: {}".format(i.getRecordType()))
    print("MC Address: {}".format(i.getMulticastAddress()))
    for e in i.source_addresses:
        print("Source: {}".format(e.getAddress()))
    n+=1
print("/*                              */")
print("/* Created same object in bytes */")
print("/*                              */")
pck_bytes = packet.bytes()
print(pck_bytes)
report = PacketIGMPv3HeaderReport.parse_bytes(pck_bytes)
print("Group Records: ")
n = 1
for i in report.group_records:
    print("Type: {}".format(i.getRecordType()))
    print("MC Address: {}".format(i.getMulticastAddress()))
    for e in i.source_addresses:
        print("Source: {}".format(e.getAddress()))
    n += 1
######################################################
######################################################
######################################################
print("/*                                */")
print("/* Created IGMP Header with Query */")
print("/*                                */")
# packet = IGMP Query
