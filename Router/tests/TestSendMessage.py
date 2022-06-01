
# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/IGMPv3/igmpv3/ . -r
# cd igmpv3/

from packet.PacketGroupRecord import PacketGroupRecord
from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from packet.PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from packet.PacketIGMPHeader import PacketIGMPHeader
from InterfaceIGMP import InterfaceIGMP
import netifaces


print("Starting interface")
print(netifaces.interfaces())
interface = InterfaceIGMP("eth0", 0)

print("Interface IP: {}".format(interface.get_ip()))
packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "223.0.4.1")
source_1 = PacketIGMPMSourceAddress("192.3.34.1")
source_2 = PacketIGMPMSourceAddress("192.3.34.2")
print("Message to send: ")

print("     0                   1                   2                   3")
print("     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1")
print("    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
print("    |                 Group Address: {}                      |".format(packet.getGroupAddress()))
print("    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
packet_hdr = PacketIGMPHeader(packet)
pkt_to_bytes = packet_hdr.bytes()
print(pkt_to_bytes)
interface.send(pkt_to_bytes, "10.0.0.1")


print("Sending a Report . . .")
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

packet_hdr = PacketIGMPHeader(packet)
pkt_to_bytes = packet_hdr.bytes()
print(pkt_to_bytes)
interface.send(pkt_to_bytes, "10.0.0.1")
