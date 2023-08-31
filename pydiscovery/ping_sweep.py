import subprocess
import ipaddress

def ping_scan(ip_range):
    active_hosts = []
    ip_net = ipaddress.ip_network(ip_range, strict=False)
    for ip in ip_net.hosts():
        ip_str = str(ip)
        try:
            subprocess.check_output(["ping", "-c", "1", "-W", "1", ip_str], stderr=subprocess.STDOUT)
            active_hosts.append(ip_str)
        except subprocess.CalledProcessError:
            pass
    return active_hosts

def main():
    print("Network Discovery Tool")
    ip_input = input("Enter an IP address or IP range (e.g., 192.168.0.0/24): ")
    method_input = input("Select the discovery method (ping): ").lower()

    if method_input == "ping":
        active_hosts = ping_scan(ip_input)
        print("Active hosts found:")
        for host in active_hosts:
            print(host)

if __name__ == "__main__":
    main()
