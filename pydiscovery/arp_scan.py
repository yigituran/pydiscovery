from scapy.all import *

def arp_scan(ip_range):
    active_hosts = {}

    # Create an ARP request packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send the packet and receive responses
    ans, _ = srp(packet, timeout=2, verbose=False)

    for response in ans:
        ip_address = response[1][ARP].psrc
        mac_address = response[1][ARP].hwsrc
        #active_hosts.append((ip_address, mac_address))
        active_hosts[ip_address] = mac_address

    return active_hosts

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"

    active_hosts = arp_scan(ip_range)
    for ip, mac in active_hosts:
        print(f"IP: {ip}, MAC: {mac}")
