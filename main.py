from pysnmp.hlapi import *
from scapy.all import *

def get_routing_tables(ip, community):
    
    
    def get_routing_table_rec(visited, ip, paramOid):
        next_oid = None
        for (errorIndication, errorStatus,errorIndex, varBinds) in bulkCmd(SnmpEngine(),
                          CommunityData(community),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          0,10,
                          ObjectType(ObjectIdentity(paramOid)),
                          lexicographicMode=False):

            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
               
                if " =" not in str(varBinds[0]):
                    continue
             
                temp = str(varBinds[0]).split("=")[1].strip()
                if temp ==  "0.0.0.0" or temp in visited:
                    continue

                next_ip = temp
                visited.add(next_ip)
                #print(varBinds[0])
                next_oid = str(varBinds[-1][0])
                print("next hop of ip address " + ip + " is ip: " +  next_ip)

        if next_oid is not None:
            get_routing_table_rec(visited, next_ip, next_oid[:22])

    initial_oid = '1.3.6.1.2.1.4.24.4.1.4'
    visited = set([ip])
    get_routing_table_rec(visited, ip, initial_oid)


#get hw info 
fam, hw = get_if_raw_hwaddr(conf.iface)

# Define a callback function
def dhcp_print(packet):

    for opt in packet[DHCP].options:
        if opt[0] == 'router':
            print("ip address of a local gateway: " + opt[1])
            get_routing_tables(opt[1], "PSIPUB")
        if opt == 'end': 
            break
        elif opt == 'pad': #byte padding
            break


# craft DHCP request
ether = Ether(dst='ff:ff:ff:ff:ff:ff')
ip = IP(src='0.0.0.0', dst='255.255.255.255')
udp = UDP(sport=68, dport=67)
bootp = BOOTP(chaddr=hw)
dhcp = DHCP(options=[("message-type","discover")])

dhcp_request = ether/ip/udp/bootp/dhcp

# Send DHCP request
sendp(dhcp_request)

# Set a filter and sniff for any DHCP packets
sniff(prn=dhcp_print, filter='udp and (port 67 or 68)', count=1)
