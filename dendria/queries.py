from storage import deref

def gethostbyv4addr(db, ipaddr):
    if not isinstance(ipaddr, str):
        ipaddr = str(ipaddr)
    addrinfo = db.v4addr.find_one({"address": ipaddr}, {"hosts": 1})
    if addrinfo is not None:
        return [deref(db, h) for h in addrinfo["hosts"]]

def gethostbymacaddr(db, macaddr, query=None):
    addrinfo = db.macaddr.find_one({"address": macaddr}, {"host": 1})
    if addrinfo is not None:
        return db.hosts.find_one({"_id": addrinfo["host"].id}, query)

def mac2ident(db, macaddr):
    addrinfo = db.macaddr.find_one({"address": macaddr}, {"host": 1})
    if addrinfo is not None:
        hostinfo = db.hosts.find_one({"_id": addrinfo["host"].id}, {"ident": 1})
        if hostinfo is not None:
            return hostinfo["ident"]

def mac2iface(db, macaddr):
    addrinfo = db.macaddr.find_one({"address": macaddr}, {"host": 1})
    if addrinfo is not None:
        hostinfo = db.hosts.find_one({"_id": addrinfo["host"].id},
                                     {"ident": 1,
                                      "name": 1,
                                      "interfaces.ifindex": 1,
                                      "interfaces.name": 1,
                                      "interfaces.mac": 1})
        ifaces = hostinfo.get("interfaces", [])
        ifaces.sort(lambda x,y: cmp(x.get("ifindex"), y.get("ifindex")))
        for iface in ifaces:
            if iface.get("mac") == macaddr:
                return {
                    "ident": hostinfo["ident"],
                    "name":  hostinfo["name"],
                    "ifindex": iface["ifindex"],
                    "ifname": iface["name"],
                    "mac": macaddr
                    }

def getlladj(db, hostid):
    """
    Return link layer adjacencies for the given host
    """
    host = gethostbymacaddr(db, hostid, {"name": 1, "interfaces": 1})
    if host is None:
        return []

    adj = { hostid: { "name": host["name"] } }
    for iface in host.get("interfaces", []):
        for arpent in iface.get("arp", []):
            niface = mac2iface(db, arpent["mac"])
            if niface is None: ## neighbour not in database
                adj[hostid][arpent["mac"]] = {
                    "src": {
                        "ifindex": iface["ifindex"],
                        "ifname":  iface["name"],
                        "mac":     iface["mac"]
                        },
                    "dst": {
                        "mac": arpent["mac"]
                        }
                    }
            else:
                adj[hostid][niface["ident"]] = {
                    "name": niface["name"],
                    "src": {
                        "ifindex": iface["ifindex"],
                        "ifname":  iface["name"],
                        "mac":     iface["mac"]
                        },
                    "dst": {
                        "ifindex": niface["ifindex"],
                        "ifname":  niface["ifname"],
                        "mac":     niface["mac"]
                        }
                    }
    return adj

def freqinfo(db, frequency = None):
    if frequency is not None:
        query = { "interfaces.freq": frequency }
    else:
        query = { "interfaces.freq": { "$exists": True } }
    hostfreq = db.hosts.find(query, {
            "ident":              True,
            "name":               True,
            "interfaces.ifindex": True,
            "interfaces.name":    True,
            "interfaces.mac":     True,
            "interfaces.freq":    True,
            "interfaces.ssid":    True,
            })
    freqinfo = {}
    for host in hostfreq:
        for iface in host["interfaces"]:
            f = iface.get("freq")
            if f is None:
                continue
            freqlist = freqinfo.setdefault(f, [])
            freqlist.append({
                    "ident": host["ident"],
                    "name": host["name"],
                    "iface": iface["name"],
                    "ifindex": iface["ifindex"],
                    "mac": iface.get("mac"),
                    "ssid": iface.get("ssid", "Unknown")
                    })
    freqs = freqinfo.keys()
    freqs.sort()
    for f in freqs:
        freqlist = freqinfo[f]
        def ifcmp(x,y):
            v = cmp(x["ssid"], y["ssid"])
            if v != 0:
                return v
            return cmp(x["ident"], y["ident"])
        freqlist.sort(ifcmp)

    return freqinfo
