from scapy.all import *

def tcp_syn_scan(ip_range, ports):
    open_ports = {}

    # Create a TCP SYN packet
    packet = IP(dst=ip_range) / TCP(dport=ports, flags="S")

    # Send the packet and receive responses
    ans, _ = sr(packet, timeout=2, verbose=False)

    for response in ans:
        if response[1][TCP].flags == "SA":  # TCP SYN-ACK (flags = 0x12)
            ip_address = response[0][IP].dst
            port = response[0][TCP].dport
            if ip_address not in open_ports:
                open_ports[ip_address] = []
            open_ports[ip_address].append(port)

    return open_ports

if __name__ == "__main__":
    ip_range = "192.168.1.1"
    ports = [80, 443, 8080]

    open_ports = tcp_syn_scan(ip_range, ports)
    for host, ports in open_ports.items():
        print("Host:", host, "Open Ports:", ports)
