from pydiscovery import app, celery
from pydiscovery import ping_sweep, arp_scan, tcp_scan, snmp_discovery
from flask import flash
import datetime
from pydiscovery.models import DiscoveryResult, User
from pydiscovery import db

@celery.task
def perform_discovery(method_input, ip_input, ports_input, username):
    if method_input == "ping":
        active_hosts = ping_sweep.ping_scan(ip_input)
        result_text = '\n'.join(active_hosts)
    elif method_input == "port":
        try:
            ports = [int(p) for p in ports_input.split(",")]
            active_hosts = tcp_scan.tcp_syn_scan(ip_input, ports)
            result_text = ""
            for ip, ports in active_hosts.items():
                result_text += f"IP: {ip}, Open Ports: {ports}\n"
        except:
            flash("Please enter ports as comma-separated. E.g: '22, 23'")
            return
    elif method_input == "arp":
        active_hosts = arp_scan.arp_scan(ip_input)
        result_text = '\n'.join(active_hosts)
    elif method_input == "snmp":
        active_hosts = snmp_discovery.snmp_scan(ip_input)
        result_text = '\n'.join(active_hosts)
    else:
        active_hosts = []  # Default case
        result_text = ""

    current_user = User.query.filter_by(username=username).first()
    discovery_result = DiscoveryResult(method=method_input, ip_range=ip_input, result=result_text, user=current_user)
    db.session.add(discovery_result)
    db.session.commit()

    flash("Discovery task completed. Results are available.", "info")
