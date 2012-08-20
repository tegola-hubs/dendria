import netsnmp
import ipaddress as ip
import time
from utils import unpackmac, is_bogon

log = __import__("logging").getLogger(__name__)

class SnmpError(Exception):
    pass

def interrogate_snmp(host, version=1, community='public', **kw):
    def get(v):
        r, = netsnmp.snmpget(v, Version=version, DestHost=host, Community=community)
        return r
    def walk(v):
        return netsnmp.snmpwalk(v, Version=version, DestHost=host, Community=community)

    log.info("[%s]: getting system description..." % host)
    sysdesc = get('SNMPv2-MIB::sysDescr.0')
    if sysdesc is None:
        log.warning("[%s] no response" % host)
        raise SnmpError("[%s] no response" % host)

    sysmib = (
        ("name", 'SNMPv2-MIB::sysName.0'),
        ("location", 'SNMPv2-MIB::sysLocation.0'),
        ("contact", 'SNMPv2-MIB::sysContact.0'),
        )
    result = dict((k,get(v)) for k,v in sysmib)
    result["sysdesc"] = sysdesc

    log.info("[%s]: getting interfaces..." % host)
    ifaces = {}
    indexes = walk('IF-MIB::ifIndex')
    for i in range(len(indexes)):
        ifindex = indexes[i]
        ifmib = (
            ("name", 'IF-MIB::ifDescr.%s' % ifindex),
            ("ifindex", 'IF-MIB::ifIndex.%s' % ifindex),
            ("type", 'IF-MIB::ifType.%s' % ifindex),
            ("mtu", 'IF-MIB::ifMtu.%s' % ifindex),
            ("speed", 'IF-MIB::ifSpeed.%s' % ifindex),
            ("mac", 'IF-MIB::ifPhysAddress.%s' % ifindex),
#                'IF-MIB::ifAdminStatus',
#                'IF-MIB::ifOperStatus',
            )
        ifdesc = dict((k,get(v)) for k,v in ifmib)
        ifdesc['ifindex'] = int(ifdesc['ifindex'])
        if ifdesc['mac'] is None:
            del ifdesc['mac']
        else:
            ifdesc['mac'] = unpackmac(ifdesc['mac'])
        if ifdesc['mtu'] is None:
            del ifdesc['mtu']
        else:
            ifdesc['mtu'] = int(ifdesc['mtu'])
        if ifdesc['speed'] == None:
            del ifdesc['speed']
        else:
            ifdesc['speed'] = int(ifdesc['speed'])
            if ifdesc['speed'] == 0:
                del ifdesc['speed']
        ifaces[ifindex] = ifdesc
    result['interfaces'] = ifaces.values()

    log.info("[%s]: getting IPv4 addresses..." % host)
    addrs = walk('IP-MIB::ipAdEntAddr')
    for n in range(len(addrs)):
        addr = addrs[n]
        if is_bogon(addr):
            continue
        addrmib = (
                'IP-MIB::ipAdEntIfIndex.%s' % addr,
                'IP-MIB::ipAdEntAddr.%s' % addr,
                'IP-MIB::ipAdEntNetMask.%s' % addr
                )
        addrdesc = list(get(v) for v in addrmib)

        addr = ip.ip_interface("%s/%s" % (addrdesc[1], addrdesc[2]))
        iface = ifaces[addrdesc[0]]
        iface.setdefault('v4addr', []).append(str(addr))

    log.info("[%s]: getting ARP table..." % host)
    ifindices = set(walk('IP-MIB::ipNetToMediaIfIndex'))
    for i in range(len(ifindices)):
        ifindex = ifindices.pop()
        ipaddrs = walk('IP-MIB::ipNetToMediaNetAddress.%s' % ifindex)
        macaddrs = walk('IP-MIB::ipNetToMediaPhysAddress.%s' % ifindex)
        for n in range(len(ipaddrs)):
            iface = ifaces[ifindex]
            ipaddr = ip.ip_address(ipaddrs[n])
            macaddr = unpackmac(macaddrs[n])
            neighbours = iface.setdefault("arp", [])
            neighbours.append({
                    "v4addr": str(ipaddr),
                    "mac": macaddr,
                    })
        
    log.info("[%s]: getting IPv4 routing table..." % host)
    routes = walk(netsnmp.Varbind('IP-MIB::ip.21.1.1'))
    for n in range(len(routes)):
        net = routes[n]
        if is_bogon(net):
            continue
        rtmib = (
            'IP-MIB::ip.21.1.11.%s' % net, # netmask
            'IP-MIB::ip.21.1.7.%s' % net,  # next hop
            )
        rtdesc = list(get(v) for v in rtmib)
        rtable = result.setdefault("v4routes", [])
        network = ip.ip_network("%s/%s" % (net, rtdesc[0]))
        nexthop = ip.ip_address(rtdesc[1])
        rtable.append({
                "network": str(network),
                "nexthop": str(nexthop)
                })

    result["timestamp"] = time.time()
    return result
