from pysnmp.hlapi import *

def snmp_scan(ip_range):
    active_hosts = []

    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData('public', mpModel=0),
                              UdpTransportTarget((ip_range.split("/")[0], 16100)),
                              ContextData(),
                              ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))):
        if errorIndication:
            continue
        if errorStatus:
            continue

        for varBind in varBinds:
            active_hosts.append(varBind[1].prettyPrint())

    return active_hosts
