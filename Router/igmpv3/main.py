# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/Router/igmpv3/ . -r
# cd igmpv3/
from InterfaceIGMP import InterfaceIGMP
import netifaces

def chooseInterface():
    interfaces = netifaces.interfaces()

    def printInterfaces():
        print('Choose the network interface:')
        for i in range(len(interfaces)):
            print(i+1, '-', interfaces[i])

    if len(interfaces) == 1:  # user has just 1 interface and any
        return interfaces[0]
    else:
        printInterfaces()
        inputValue = input('Interface number: ')

        if int(inputValue)-1 not in range(len(interfaces)):
            raise Exception('Invalid interface number')
        inputValue = interfaces[int(inputValue)-1]
        return inputValue


interface_name = chooseInterface()


print("Starting interface {}".format(interface_name))
interface = InterfaceIGMP(interface_name, 0)

print("Interface IP: {}".format(interface.get_ip()))

print("/*   IGMPv3 protocol has been initialized!  */")
print("/*   You can insert a command at any time.  */")
print("/*   The possible commands are these ones:  */")
# HERE WILL BE THE LIST OF COMMANDS ! ! !
print("/*          show mcgroups                   */")
print("/*          show groupstate (mc_address)    */")
print("\n")
print("/*   You can check back the commands using  */")
print("/*   the 'man' command in shell prompt.     */")
print("\n")
while True:
    action = input("")
    event = action.split()
    if action:
        if event[0] == "show" and event[1] == "mcgroups":
            # show mc groups ip
            print("/*                                          */")
            print("/*   MULTICAST GROUPS' IP TABLE             */")
            print("/*                                          */")
            for key in interface.interface_state.group_state:
                print("/*   GROUP IP     |      {}".format(key))
            print("\n")
        elif event[0] == "show" and event[1] == "groupstate":
            group = event[2]
            for key in interface.interface_state.group_state:
                if key == group:
                    c = 1
                    print("/*                                          */")
                    print("/*   GROUP IP     |      {}".format(key))
                    print("/*   GROUP MODE   |      {}".format(interface.interface_state.group_state[key].filter_mode))
                    for source in interface.interface_state.group_state[key].source_addresses:
                        print("/*   SOURCE {}|      {}".format(c, source))
                        c+=1
                    print("\n")
        elif event[0] == "man":
            print("/*          show mcgroups                   */")
            print("/*          show groupstate (mc_address)    */")
            print("\n")
