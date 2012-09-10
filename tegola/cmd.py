"""
.. program:: tegola

:program: `tegola`
==================

Command line interface for finding things out about the network.
There are several sub-commands...
"""
import argparse
import logging
import json
import time
import sys
import ipaddress as ip
from utils import loglines
from pprint import pprint
from storage import get_db, pkey_check, PKeyError, mergedict, deref
from traceback import format_exc
from queries import freqinfo, gethostbymacaddr, gethostbyv4addr

log = logging.getLogger(__name__)

def _cli():
    parser = argparse.ArgumentParser(description="Tegola CLI")
    parser.add_argument('--debug', dest='debug', action='store_true',
                        default=False, help='Turn on debugging')
    parser.add_argument('--dbhost', dest='dbhost', default='localhost',
                        help="default: localhost")
    parser.add_argument('--dbport', dest='dbport', type=int, default=27017,
                        help="default: 27017")
    parser.add_argument('--dbname', dest='dbname', default='tegola',
                        help="default: tegola")
    subparsers = parser.add_subparsers(help="sub-command help")
    
    from tegola import cmd as module
    for pname in [x for x in dir(module) if x.endswith("_parser")]:
        cmdname = pname[:-7]
        p = getattr(module, pname)
        if p.__doc__:
            doc = p.__doc__
        else:
            doc = '%s help' % cmdname
        subparser = subparsers.add_parser(cmdname, help=doc)
        p(subparser)

    args = parser.parse_args()

    loglevel = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='%(asctime)-15s %(name)s [%(levelname)s] %(message)s',
                        level=loglevel)
    args.func(args)

def auth(args):
    if (args.username and not args.password) or \
            (not args.username and args.password):
        sys.stderr.write("Error: both username and password must be specified\n")
        return
    db = get_db(args)
    authinfo = db.authinfo.find_one({"name": args.name})
    if authinfo is None:
        authinfo = {"name": args.name}
    if args.show:
        pprint(authinfo)
    elif args.add:
        if args.community is not None:
            clist = authinfo.get("community", [])
            clist.append(args.community)
            authinfo["community"] = list(set(clist))
        if args.username is not None:
            uplist = [tuple(x) for x in authinfo.get("login", [])]
            uplist.append((args.username, args.password))
            authinfo["login"] = list(set(uplist))
        db.authinfo.save(authinfo)
    elif args.replace:
        if args.community is not None:
            authinfo["community"] = [args.community]
        if args.username is not None:
            authinfo["login"] = [(args.username, args.password)]
        db.authinfo.save(authinfo)
    elif args.delete:
        db.authinfo.remove(authinfo)
    else:
        args.parser.print_help()

def auth_parser(p):
    """Add login credentials and SNMP communities to the database."""
    p.add_argument("-a", dest="add", action="store_true", default=False,
                   help="Add credentials")
    p.add_argument("-r", dest="replace", action="store_true", default=False,
                   help="Replace credentials")
    p.add_argument("-s", dest="show", action="store_true", default=False,
                   help="Show Credentials")
    p.add_argument("-d", dest="delete", action="store_true", default=False,
                   help="Delete Credentials")
    
    p.add_argument("-c", dest="community", help="SNMP Community")
    p.add_argument("-u", dest="username", help="Login Username")
    p.add_argument("-p", dest="password", help="Login Password")
    p.add_argument("-n", dest="name", default="default",
                   help="Hostname (or default)")

    p.set_defaults(func=auth)
    p.set_defaults(parser=p)

def merge_host(db, ident):
    saved = []
    for source in ("snmp", "login", "annotations"):
        collection = getattr(db, source)
        d = collection.find_one({"ident": ident})
        if d is not None:
            del d["_id"]
            saved.append(d)
    merged = mergedict(saved)
    old = db.hosts.find_one({"ident": ident}, {"_id": True})
    if old is not None:
        merged["_id"] = old["_id"]
    merged["timestamp"] = time.time()

    ## xxx should this be here? make sure interfaces are sorted
    ifaces = merged.get("interfaces")
    if ifaces is not None:
        ifaces.sort(lambda x,y: cmp(x.get("ifindex", 0), y.get("ifindex", 0)))
        merged["interfaces"] = ifaces
    db.hosts.save(merged)
    return merged

def interrogate(args):
    db = get_db(args)
    hostname = args.hostname[0]
    authinfo = db.authinfo.find_one({"name": hostname})
    if authinfo is None:
        authinfo = {"name": hostname}
    default = db.authinfo.find_one({"name": "default"})
    if default is None:
        authinfo = {}

    descriptions = {}
    if args.snmp:
        for community in authinfo.get("community", []) + default.get("community", []):
            log.info("querying with SNMP community: %s" % community)
            try:
                from snmp import interrogate_snmp
                descriptions["snmp"] = interrogate_snmp(hostname, community=community)
                authinfo["community"] = [community]
                break
            except:
                pass

    if args.login:
        for u,p in authinfo.get("login", []) + default.get("login", []):
            log.info("logging in as user: %s" % u)
            try:
                from rlogin import interrogate_rlogin
                descriptions["login"] = interrogate_rlogin(host=hostname,
                                                           username=u, password=p)
                authinfo["login"] = [(u,p)]
                break
            except:
                pass

    db.authinfo.save(authinfo)

    try:
        ident = pkey_check(descriptions)
    except PKeyError, e:
        log.warning("%s\n%s" % (e, format_exc(e)))
        return

    for k,v in descriptions.items():
        collection = getattr(db, k)
        v["ident"] = ident
        old = collection.find_one({"ident": ident}, {"_id": True})
        if old is not None:
            v["_id"] = old["_id"]
        collection.save(v)   

    if args.merge:
        merged = merge_host(db, ident)

        if "snmp" in descriptions:
            merged["snmp"] = True
        if "login" in descriptions:
            merged["login"] = True

        from pymongo.database import DBRef
        for iface in merged["interfaces"]:
            for v4if in [ip.ip_interface(i) for i in iface.get("v4addr", [])]:
                addrinfo = db.v4addr.find_one({"address": str(v4if.ip)})
                if addrinfo is None:
                    addrinfo = {"address": str(v4if.ip)}
                hosts = addrinfo.setdefault("hosts", [])
                hosts.append(DBRef("hosts", merged["_id"]))
                addrinfo["hosts"] = list(set(hosts))
                db.v4addr.save(addrinfo)
            macaddr = iface.get("mac")
            if macaddr is not None:
                addrinfo = db.macaddr.find_one({"address": macaddr})
                if addrinfo is None:
                    addrinfo = {"address": macaddr}
                addrinfo["host"] = DBRef("hosts", merged["_id"])
                db.macaddr.save(addrinfo)
    else:
        ### used for discovery
        merged = mergedict(descriptions.values())

    return merged

def interrogate_parser(p):
    p.add_argument("hostname", nargs=1)
    p.add_argument("-s", dest="snmp", action="store_false", default=True,
                   help="Do not use SNMP")
    p.add_argument("-l", dest="login", action="store_false", default=True,
                   help="Do not use remote login (SSH)")
    p.add_argument("-m", dest="merge", action="store_false", default=True,
                   help="Do not merge descriptions")
    p.set_defaults(func=interrogate)

def host(args):
    db = get_db(args)
    ipaddr = args.ipaddress[0]
    hostinfo = []
    if args.mac:
        addrinfo = db.macaddr.find_one({"address": ipaddr})
        if addrinfo is not None:
            hostinfo = [addrinf["host"]]
    else:
        addrinfo = db.v4addr.find_one({"address": ipaddr})
        if addrinfo is not None:
            hostinfo = addrinfo["hosts"]

    hostinfo = [deref(db, h) for h in hostinfo]
    if args.snmp:
        hostinfo = [db.snmp.find_one({"ident": h["ident"]}) for h in hostinfo]
    elif args.login:
        hostinfo = [db.login.find_one({"ident": h["ident"]}) for h in hostinfo]

    if args.json:
        for h in hostinfo:
            h["_id"] = str(h["_id"])
        print json.dumps(hostinfo)
    elif args.pprint:
        for host in hostinfo:
            if host is not None:
                pprint(host)
    else:
        for host in hostinfo:
            if host is not None:
                hprint(db, host)

def hprint(db, host):
    print "=" * 80
    print "%(name)s" % host
    print "=" * 80
    print
    if host.get("sysdesc") is not None:
        print "\t%(sysdesc)s" % host
    if host.get("model") is not None:
        print "\t%(model)s" % host
    host.setdefault("opsys", "Unknown OS")
    host.setdefault("osver", "Unknown Version")
    host.setdefault("flavour", "Generic")
    host.setdefault("release", "")
    host.setdefault("machine", "Unknown Architecture")
    print "\t%(flavour)s %(release)s %(opsys)s %(osver)s %(machine)s" % host
    host.setdefault("build", "")
    print "\t%(build)s" % host
    print
    print "Interfaces:"
    ifaces = host.get("interfaces", [])
    ifaces.sort(lambda x,y: cmp(x["ifindex"], y["ifindex"]))
    for iface in ifaces:
        iface.setdefault("mac", "")
        print "  %(ifindex)s\t%(name)s" % iface
        if "ssid" in iface:
            print "\t  Wireless:\n\t\t%(ssid)s %(freq)s" % iface
        addrs = iface.get("v4addr")
        if addrs is not None:
            print "\t  IPv4 Addresses:\n\t\t" + " ".join(addrs)
        neighbours = iface.get("arp")
        if neighbours is not None:
            neighbours.sort(lambda x,y: cmp(ip.ip_address(x["v4addr"]), ip.ip_address(y["v4addr"])))
            print "\t  ARP Table:"
            for neighbour in neighbours:
                n = gethostbymacaddr(db, neighbour["mac"])
                if n is not None:
                    neighbour["name"] = " (%(name)s)" % n
                else:
                    neighbour["name"] = ""
                print "\t\t%(mac)s - %(v4addr)-16s%(name)s" % neighbour

    bridges = host.get("bridges")
    if bridges is not None:
        print
        print "Ethernet bridges:"
        for bridge in bridges:
            print "  %(name)s" % bridge
            print "\tMembers: " + " ".join(bridge.get("members", []))

    router = host.get("router")
    if router is not None:
        ospf = router.get("ospf")
        if ospf is not None:
            print
            print "OSPF Neighbours:"
            neighbours = ospf["neighbours"]
            neighbours.sort(lambda x,y: cmp(ip.ip_address(x["routerid"]),ip.ip_address(y["routerid"])))
            for neighbour in neighbours:
                ns = gethostbyv4addr(db, neighbour["v4addr"])
                if ns is not None:
                    neighbour["name"] = " (%s)" % ",".join(n["name"] for n in ns)
                else:
                    neighbour["name"] = ""
                print "\t%(ifname)8s %(routerid)-16s - %(v4addr)-16s%(name)s" % neighbour

def host_parser(p):
    p.add_argument("ipaddress", nargs=1)
    p.add_argument("-m", dest="mac", action="store_true", default=False,
                   help="Lookup by MAC address instead of IP address")
    p.add_argument("-j", dest="json", action="store_true", default=False,
                   help="Dump JSON description of host")
    p.add_argument("-p", dest="pprint", action="store_true", default=False,
                   help="Pretty print the python dictionary description")
    p.add_argument("-s", dest="snmp", action="store_true", default=False,
                   help="Show information gathered via SNMP")
    p.add_argument("-l", dest="login", action="store_true", default=False,
                   help="Show information gathered via login")
    p.set_defaults(func=host)

def discover(args, seen=set([])):
    hostname = args.hostname[0]
    print seen
    if hostname in seen:
        log.info("Already seen %s skipping" % hostname)
        return
    seen.add(hostname)
    if ip.ip_address(hostname) not in ip.ip_network(args.quarantine):
        return
    hinfo = interrogate(args)
    if hinfo is None:
        return
    if args.save:
        config(args)
    for interface in hinfo.get("interfaces", []):
        for ifaddr in [ip.ip_interface(a) for a in interface.get("v4addr", [])]:
            seen.add(str(ifaddr.ip))
        for arpent in interface.get("arp", []):
            addr = arpent.get("v4addr")
            if addr is not None:
                if addr not in seen:
                    args.hostname = [addr]
                    discover(args, seen)

def discover_parser(p):
    """Walk the network, discovering hosts, and optionally saving configurations"""
    interrogate_parser(p)
    p.add_argument("-q", dest="quarantine", default="10.0.0.0/8",
                   help="Quarantine discovery to the given network")
    ## for config save
    p.add_argument("-c", dest="save", action="store_true", default=False,
                   help="Save the configurations")
    p.add_argument("-d", dest="path", nargs=1, default="/var/tegola/config",
                   metavar="PATH", help="Save configs to the given directory")
    p.set_defaults(func=discover)

def route(args):
    db = get_db(args)
    quarantine = ip.ip_network(args.quarantine)
    routes = set([])
    for host in db.hosts.find({}, {"v4routes":1}):
        for route in host.get("v4routes", []):
            network = ip.ip_network(route["network"])
            if network.network_address in quarantine:
                routes.add(network)
    routes = list(routes)
    routes.sort()

    ## remove supernets... this is a bit weird...
    def supernets(n):
        s = n.supernet()
        if s == n:
            return
        yield s
        for s in supernets(s):
            yield s

    ## hella ineffient
    prune = set([])
    for r in routes:
        ## except interface routes...
        if r.prefixlen == 32:
            continue
        for s in supernets(r):
            prune.add(s)
    for p in prune:
        if p in routes:
            routes.remove(p)

    addrs = set([])
    for addr in db.v4addr.find():
        addrs.add(ip.ip_address(addr["address"]))
    addrs = list(addrs)
    addrs.sort()

    for r in routes:
        print r
        for addr in addrs:
            if addr in r:
                hinfo = gethostbyv4addr(db, addr)
                for host in hinfo:
                    print "\t%-16s%s" % (addr, host["name"])

def route_parser(p):
    """Query IP network usage."""
    p.add_argument("-q", dest="quarantine", default="10.0.0.0/8",
                   help="Report on subnets within this network")
    p.set_defaults(func=route)

def serve(args):
    from werkzeug.serving import run_simple
    from server import TegolaRest

    db = get_db(args)
    app = TegolaRest(db, mountpoint=args.mountpoint)
    if args.socket:
        from flup.server.fcgi import WSGIServer
        WSGIServer(app, bindAddress=args.socket).run()
    else:
        run_simple(args.listen, args.port, app, 
                   use_debugger=args.debug, use_reloader=args.debug)
    
def serve_parser(p):
    """Run the JSON HTTP API service"""
    p.add_argument("-l", dest="listen", default="127.0.0.1",
                   help="HTTP Listen Address")
    p.add_argument("-p", dest="port", default=5000, type=int,
                   help="HTTP Listen Port")
    p.add_argument("-s", dest="socket", help="FCGI Socket")
    p.add_argument("-m", dest="mountpoint", help="URL Mountpoint",
                   default="")
    p.set_defaults(func=serve)

def spectrum(args):
    db = get_db(args)

    if args.frequency is not None:
        if not args.frequency.endswith("GHz"):
            args.frequency = args.frequency + " GHz"

    info = freqinfo(db, args.frequency)
    freqs = info.keys()
    freqs.sort()
    for f in freqs:
        print f
        freqlist = info[f]
        for host in freqlist:
            print "\t%(ssid)-30s s%(mac)s %(name)s (%(iface)s)" % host
            
def spectrum_parser(p):
    """Report on frequency usage."""
    p.add_argument("-f", dest="frequency",
                   help="Frequency")
    p.set_defaults(func=spectrum)

def config(args):
    db = get_db(args)

    hostname = args.hostname[0]
    authinfo = db.authinfo.find_one({"name": hostname})
    if authinfo is None or authinfo.get("login") is None:
        log.error("Do not have a username for this host, interrogate it first, please")
        return

    hinfo = gethostbyv4addr(db, hostname)
    if hinfo is None:
        hinfo = gethostbymacaddr(db, hostname)
        if hinfo is None:
            log.error("Interrogate this host first, please")
            return
    elif len(hinfo) == 1:
        hinfo = hinfo[0]
    elif len(hinfo) > 1:
        log.error("Several matching hosts found:")
        for h in hinfo:
            log.error("    %s" % h["ident"])
        log.error("Try using the identifier instead.")

    import os, os.path
    def trymkdir(d):
        try:
            os.stat(d)
        except OSError:
            os.makedirs(d)

    if isinstance(args.path, list):
        cfgpath = args.path[0]
    else:
        cfgpath = args.path
    trymkdir(cfgpath)

    ### XXXX should be in the database!
    dontuse = [ip.ip_address(a) for a in ("10.10.10.10", "10.127.127.10", "10.123.123.123")]
    mgmtnet = ip.ip_network("10.0.0.0/8")
    def getaddr(hinfo):
        for iface in hinfo.get("interfaces", []):
            for ifa in [ip.ip_interface(a) for a in iface.get("v4addr", [])]:
                if ifa.ip in mgmtnet and ifa.ip not in dontuse:
                    return ifa.ip
    
    from rlogin import Rcmd
    import pexpect

    if hinfo.get("flavour") is None:
        log.warning("[%(name)s] Couldn't determine which OS variant to use for backing up, sorry." % hinfo)
    elif hinfo["flavour"].lower() == "openwrt" or hinfo["flavour"] == "NanoBSD":
        cfgpath = os.path.join(cfgpath, hinfo["ident"])
        trymkdir(cfgpath)
        c = Rcmd(host=getaddr(hinfo),
                 path=cfgpath,
                 username=authinfo["login"][0][0],
                 password=authinfo["login"][0][1],
                 cmd="sh -c 'ssh %(username)s@%(host)s tar -cf - /etc | (cd %(path)s; tar -xf -)'",
                 timeout=300)
        try:
            c.run()
        except pexpect.EOF:
            pass
    elif hinfo["flavour"] == "AirOS":
        cfgpath = os.path.join(cfgpath, hinfo["ident"]) + ".cfg"
        c = Rcmd(host=getaddr(hinfo),
                 path=cfgpath,
                 username=authinfo["login"][0][0],
                 password=authinfo["login"][0][1],
                 cmd="scp -q -r %(username)s@%(host)s:/tmp/system.cfg %(path)s",
                 timeout=300)
        try:
            c.run()
        except pexpect.EOF:
            pass
    else:
        log.warning("[%(name)s] don't know how to back up the config of a %(flavour)s host" % hinfo)
        return
    log.info("[%(name)s] done." % hinfo)

def config_parser(p):
    """Backup (and eventually restore) system configuration from remote hosts."""
    p.add_argument("-s", dest="save", action="store_true", default=False,
                   help="Save the configuration")
    p.add_argument("-d", dest="path", nargs=1, required=True,
                   metavar="PATH", help="Save config to the given directory")
    p.add_argument("hostname", nargs=1, help="Hostname")
                   
    p.set_defaults(func=config)

def oauth(args):
    db = get_db(args)

    site = db.oauth.find_one({ "name": [args.site_name] })
    if site is None:
        site = {}
    site["name"] = args.site_name[0]
    site["client_id"] = args.client_id[0]
    site["client_secret"] = args.client_secret[0]
    site["oauth_url"] = args.oauth_url[0]

    db.oauth.save(site)

def oauth_parser(p):
    p.add_argument("site_name", nargs=1, help="Site Slug")
    p.add_argument("client_id", nargs=1, help="Client ID")
    p.add_argument("client_secret", nargs=1, help="Client Secret")
    p.add_argument("oauth_url", nargs=1, help="OAuth URL")
    p.set_defaults(func=oauth)

def annotate(args):
    db = get_db(args)

    hostname = args.hostname[0]
    authinfo = db.authinfo.find_one({"name": hostname})
    if authinfo is None or authinfo.get("login") is None:
        log.error("Do not have a username for this host, interrogate it first, please")
        return

    hinfo = gethostbyv4addr(db, hostname)
    if hinfo is None:
        hinfo = gethostbymacaddr(db, hostname)
        if hinfo is None:
            log.error("Interrogate this host first, please")
            return
    elif len(hinfo) == 1:
        hinfo = hinfo[0]
    elif len(hinfo) > 1:
        log.error("Several matching hosts found:")
        for h in hinfo:
            log.error("    %s" % h["ident"])
        log.error("Try using the identifier instead.")

    annotations = db.annotations.find_one({ "ident": hinfo["ident"]})
    if annotations is None:
        annotations = { "ident": hinfo["ident"] }

    if args.json:
        value = json.loads(args.value[0])
    else:
        value = args.value[0]

    if args.key[0] in annotations and not value:
        del annotations[args.key[0]]
    else:
        annotations[args.key[0]] = value

    db.annotations.save(annotations)

    merge_host(db, hinfo["ident"])

def annotate_parser(p):
    p.add_argument("hostname", nargs=1, help="IP or MAC address")
    p.add_argument("key", nargs=1, help="Key")
    p.add_argument("value", nargs=1, help="Value")
    p.add_argument("-j", dest="json", action="store_true", default=False,
                   help="Value is JSON")
    p.set_defaults(func=annotate)
