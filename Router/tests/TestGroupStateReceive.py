# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/Router/igmpv3/ . -r
# cd igmpv3/

from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPHeader import PacketIGMPHeader
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from InterfaceIGMP import InterfaceIGMP
import netifaces
import time

print("Starting interface")
print(netifaces.interfaces())
interface = InterfaceIGMP("eth0", 0)

print("Interface IP: {}".format(interface.get_ip()))

i = 0
while True:
    time.sleep(10)
    for key in interface.interface_state.group_state:
        print(key)
        print("SOURCES:")
        for source in interface.interface_state.group_state[key].source_addresses:
            print(source)
