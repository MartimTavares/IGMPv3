# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/IGMPv3/igmpv3/ . -r
# cd igmpv3/

from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from InterfaceIGMP import InterfaceIGMP
import netifaces

print("Starting interface")
print(netifaces.interfaces())
interface = InterfaceIGMP("eth0", 0)

print("Interface IP: {}".format(interface.get_ip()))

i=0
while True:
    i+=1