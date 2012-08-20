import sys
import ipaddress as ip

def strip_domain(hostname, domains):
    for domain in domains:
        if hostname.endswith("." + domain):
            return hostname[:-len(domain)-1]
    return hostname

def forward(descr, fp=sys.stdout, anycast=[], domains=[]):
    hostname = strip_domain(descr["hostname"], domains)
    for iface in descr.get("interfaces", []):
        ifname = iface["name"]
        name = ifname + "." + hostname
        for ifaddr in iface.get("v4addr", []):
            addr = ip.ip_interface(ifaddr).ip
            if addr in anycast:
                continue
            fp.write("%s\tIN A\t%s\n" % (name, addr))
            if ifname in ["lo", "lo0", "Loopback0"]:
                fp.write("%s\tIN CNAME\t%s\n" % (hostname, name))

def zone_from_network(network):
    "XXX only does classful"
    na, nm = str(network.network_address), str(network.hostmask)
    zone = []
    for oa, om in zip(na.split("."), nm.split(".")):
        if om != "0":
            break
        zone.append(oa)
    return ".".join(zone)

def dnsent_from_addr(addr, zone):
    addrstr = addr.exploded[len(zone)+1:]
    octets = addrstr.split(".")
    octets.reverse()
    return ".".join(octets)

def reverse(descr, fp=sys.stdout, anycast=[], domains=[], 
            network=ip.ip_network("10.0.0.0/8"), domain="example.net"):
    hostname = strip_domain(descr["hostname"], domains)
    zone = zone_from_network(network)
    for iface in descr.get("interfaces", []):
        ifname = iface["name"]
        name = ifname + "." + hostname
        for ifaddr in [ip.ip_interface(a) for a in iface.get("v4addr", [])]:
            if ifaddr.ip in anycast:
                continue
            if ifaddr.ip not in network:
                continue
            dnsent = dnsent_from_addr(ifaddr.ip, zone)
            fp.write("%s\tIN PTR\t%s\n" % (dnsent, name + "." + domain + "."))

if __name__ == '__main__':
    import redis
    import json
    r = redis.Redis()

    anycast = ["10.10.10.10", "10.127.127.10", "10.123.123.123"]
    anycast = list(ip.ip_address(a) for a in anycast)
    domains = ["tegola.org.uk", "tegola"]
    domain = "tegola"

    hosts = r.smembers("hosts")
    while len(hosts) > 0:
        ident = hosts.pop()
        descr = r.hget(ident, "snmp")
        forward(json.loads(descr), anycast=anycast, domains=domains)

    print
    hosts = r.smembers("hosts")
    while len(hosts) > 0:
        ident = hosts.pop()
        descr = r.hget(ident, "snmp")
        reverse(json.loads(descr), anycast=anycast, domains=domains, domain="tegola")
