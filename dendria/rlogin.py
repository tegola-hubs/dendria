import pexpect
import fsm
import sys
import time
from string import ascii_letters
from utils import is_bogon, splitlines, tokenize

log = __import__("logging").getLogger(__name__)

class OperationalError(Exception):
    """raised when the expect session fails"""

class Rcmd(fsm.FSM):
    def __init__(self, timeout=30, **params):
        self.params = params.copy()
        self.params.setdefault("rlogin", "ssh")
        self.params.setdefault("cmd", '%(rlogin)s -l %(username)s %(host)s')
        self.timeout = timeout
        self._command = None
        self._result = None

    def error(self, msg):
        logmsg = "[%(host)s]: " % self.params + msg
        log.warning(logmsg)
        raise OperationalError(logmsg)

    def state_START(self):
        cmd = self.params["cmd"] % self.params
        log.info("[%s]: running: %s" % (self.params["host"], cmd))
        self.child = pexpect.spawn(cmd)
#        self.child.logfile = sys.stderr
        return "LOGIN"

    def state_STOP(self):
        self.child.kill(0)

    def state_LOGIN(self):
        m = self.child.expect(['Are you sure you want to continue connecting',
                               '[Pp]assword:',
                               '[#>][\t ]',
                               '\nPermission denied'], timeout=self.timeout)

        if m == 0:
            self.child.sendline("yes")
            return "LOGIN"
        if m == 1:
            self.child.sendline(self.params["password"])
            return "LOGIN"
        if m == 2:
            return "COMMAND"
        if m == 3:
            self.error("could not log in")
            return "STOP"

    def state_LOGOUT(self):
        log.info("[%s]: logout" % self.params["host"])
        self.child.sendline("exit")
        self.child.expect("\n")
        return "STOP"

    def state_COMMAND(self):
        log.debug("[%s]: %s" % (self.params["host"], self._command))
        self.child.sendline(self._command)
        self.child.expect("\r\n[^\n]*[#>][\t ]")

        def clean(result, cmd):
            ## first strip any leading CR/NL
            result = result.lstrip("\r").lstrip("\n")

            ## sometimes we even get backspaces
            def rmbs(result):
                while True:
                    try:
                        i = result.index('\x08')
                        result = result[:i-1] + result[i+1:]
                    except ValueError:
                        break
                return result
            result = rmbs(result)

            ## sometimes we get non-printable characters inserted into
            def rmchar(result, c):
                while True:
                    try:
                        i = result.index(c)
                        #if i >= len(cmd):
                        #    break
                        if result.startswith(cmd):
                            break
                        result = result[:i] + result[i+1:]
                    except ValueError:
                        break
                return result
            result = rmchar(result, "\r")
            result = rmchar(result, "\n")

            return result

        result = clean(self.child.before, self._command)

        if result.startswith(self._command):
            result = result[len(self._command):]
        result = result.lstrip("\r")
        result = result.lstrip("\n")

#        try:
#            _, result = result.split("\n", 1)
#        except ValueError:
#            result = ""

        result = result.lstrip("\r").lstrip("\n")
        self._result = result
        return "PAUSE"

    def run(self, command=None):
        if self.state == "PAUSE":
            self.state = "COMMAND"
        self._command = command
        self._result = None
        super(Rcmd, self).run()
        return self._result

    def sh(self, command):
        return self.run("sh -c '%s'" % command.replace("'", "\\'"))

    def logout(self):
        self.state = 'LOGOUT'
        self.run()

class RHost(object):
    def __init__(self, machine):
        self.machine = machine

    def hostname(self):
        if not hasattr(self, "__hostname__"):
            self.__hostname__ = self.machine.run("hostname").strip()
        return self.__hostname__

    def osinfo(self):
        return {
            "opsys": self.machine.run("uname -s").strip(),
            "osver": self.machine.run("uname -r").strip(),
            "build": self.machine.run("uname -v").strip(),
            }

    def bridges(self):
        return []

    def llinfo(self, ifname):
        return {
            "mac": self.macaddr(ifname),
            "mtu": self.mtu(ifname)
            }

    def describe(self):
        descr = {}
        descr["name"] = self.hostname()
        log.info("[%s] gathering operating system information" % self.hostname())
        descr.update(self.osinfo())
        log.info("[%s] gathering CPU information" % self.hostname())
        descr.update(self.cpuinfo())
        descr["interfaces"] = []
        log.info("[%s] gathering interface information" % self.hostname())
        for ifname in self.interfaces():
            log.info("[%s] ... %s" % (self.hostname(), ifname))
            iface = { "name": ifname }
            iface["ifindex"] = self.ifindex(ifname)
            def okaddr(a):
                addr, _ = a.split("/")
                return not is_bogon(addr)
            iface.update(self.llinfo(ifname))
            iface["v4addr"] = [a for a in self.v4addr(ifname) if okaddr(a)]
            iface["arp"] = self.arptable(ifname)
            descr["interfaces"].append(iface)
        bridges = self.bridges()
        if len(bridges) > 0:
            log.info("[%s] found %d ethernet bridges" % (self.hostname(), len(bridges)))
            descr["bridges"] = []
            for bridge in bridges:
                bridge["addresses"] = self.braddrs(bridge)
                descr["bridges"].append(bridge)
        log.info("[%s] getting IPv4 routing table" % self.hostname())
        descr["v4routes"] = self.v4routes()
        router = self.router_info()
        if router is not None:
            descr["router"] = router
        return descr

    def procs(self):
        output = self.machine.run("ps xw | awk '{ print $5; }'")
        return splitlines(output)[1:]

    def routing_daemon(self):
        if not hasattr(self, "__routing_daemon__"):
            procs = self.procs()
            if "/usr/sbin/bird" in procs or "/usr/local/sbin/bird" in procs:
                self.__routing_daemon__ = "bird"
            elif "/usr/sbin/zebra" in procs or "/usr/local/sbin/zebra" in procs:
                self.__routing_daemon__ = "quagga"
            else:
                self.__routing_daemon__ = None
            if self.__routing_daemon__ is not None:
                log.info("[%s] looks like we are using the %s routing daemon",
                         self.hostname(), self.__routing_daemon__)
        return self.__routing_daemon__

    def router_info(self):
        daemon = self.routing_daemon()
        if daemon == "bird":
            return self.bird_info()
        elif daemon == "quagga":
            return self.quagga_info()

    def bird_info(self):
        birdv = self.machine.run("echo | birdc | head -1").strip().replace(" ready.", "")
        birdv = birdv.split(" ")
        info = {
            "daemon":  birdv[0],
            "version": birdv[1],
            "ospf": {}
            }

        log.info("[%s] getting OSPF neighbours" % self.hostname())
        output = self.machine.run("echo show ospf neighbors | birdc | sed '/^bird[^ ] .*/d'")
        neighbours = []
        for toks in [tokenize(l) for l in splitlines(output)[2:]]:
            neighbour = {
                "routerid": toks[0]
                }
            if toks[4][0] in ascii_letters:
                neighbour["ifname"] =  toks[4]
                neighbour["v4addr"] =  toks[5]
            else:
                neighbour["v4addr"] =  toks[4]
                neighbour["ifname"] =  toks[5]
            neighbours.append(neighbour)
        info["ospf"]["neighbours"] = neighbours
        return info

    def quagga_info(self):
        output = self.machine.run("zebra --version")
        info = {
            "daemon": "Quagga",
            "version": tokenize(splitlines(output)[0])[-1],
            "ospf": {}
            }

        neighbours = []
        log.info("[%s] getting OSPF neighbours" % self.hostname())
        output = self.machine.run("echo show ip ospf neighbor | vtysh | grep '^[1-9]'")
        for toks in [tokenize(l) for l in splitlines(output)]:
            if len(toks) == 0:
                continue
            neighbour = {
                "routerid": toks[0],
                "v4addr":   toks[4],
                "ifname":   toks[5].split(":")[0]
                }
            neighbours.append(neighbour)
        info["ospf"]["neighbours"] = neighbours
        return info

class MetaHost(object):
    def __new__(cls, machine):
        shell = machine.run("echo $SHELL")
        if shell.endswith("csh"):
            machine.run("setenv TERM dumb")                
        else:
            machine.run("export TERM=vt100")
        opsys = machine.sh("if test -x /bin/uname -o -x /usr/bin/uname; then uname -s; else echo OldAirOS; fi")
        return eval("%s(machine)" % opsys, globals(), locals())

class FreeBSD(RHost):
    def __new__(cls, machine):
        opsys = machine.sh('if test -f /etc/nanobsd.conf; then echo NanoBSD; else echo FreeBSD; fi')
        if opsys != "FreeBSD":
            return eval("%s(machine)" % opsys, globals(), locals())
        return super(FreeBSD, cls).__new__(cls, machine)

    def cpuinfo(self):
        return {
            "machine": self.machine.run("sysctl -n hw.machine").strip(),
            "cpu": self.machine.run("sysctl -n hw.model").strip(),
            "ncpu": self.machine.run("sysctl -n hw.ncpu").strip()
            }
            
    def interfaces(self):
        if not hasattr(self, "__ifnames__"):
            output = self.machine.run("ifconfig -l")
            self.__ifnames__ = [x.strip() for x in output.split(" ")]
        return self.__ifnames__

    def ifindex(self, ifname):
        return self.interfaces().index(ifname) + 1

    def macaddr(self, ifname):
        output = self.machine.run("ifconfig %s | awk '/ether/ { print $2 }'" % ifname)
        mac = output.strip().upper()
        if len(mac) == 0:
            return None
        return mac

    def v4addr(self, ifname):
        output = self.machine.run("""ifconfig %s | awk '/^[ \\t]*inet / { print $2, $4 }'""" % ifname).strip()
        if len(output) == 0:
            return []
        def parseaddr(a):
            addr, mask = a.split(" ")
            mask = 0xffffffff - int(mask[2:], 16) + 1
            from math import log, ceil
            pfx = 32 - ceil(log(mask, 2))
            return "%s/%d" % (addr, pfx)
        return [parseaddr(x.strip()) for x in output.split("\n")]

    def mtu(self, ifname):
        output = self.machine.run("ifconfig %s | head -1 | awk '{ print $6 }'" % ifname)
        return int(output.strip())

    def arptable(self, ifname):
        output = self.machine.run("arp -an | awk  '/ on %s / { print $2, $4 }' | sed 's/[()]//g'" % ifname)
        def _neighbours():
            for line in [x.strip() for x in output.split("\n")]:
                if len(line) == 0:
                    continue
                v4addr, mac = line.split(" ")
                yield { "v4addr": v4addr, "mac": mac.upper() }
        return list(_neighbours())

    def v4routes(self):
        output = self.machine.run("netstat -f inet -anrW | tail +5 | awk '{ print $1, $2, $6 }'")
        def _routes():
            for line in [x.strip() for x in output.split("\n")]:
                network, nexthop, pmtu = line.split(" ")
                if network == "default":
                    network = "0.0.0.0/0"
                if "/" not in network:
                    network = network + "/32"
                addr, _ = network.split("/")
                if is_bogon(addr):
                    continue
                yield {
                    "network": network,
                    "nexthop": nexthop,
                    "pmtu": int(pmtu)
                    }
        return list(_routes())

class NanoBSD(FreeBSD):
    def __new__(cls, machine):
        return RHost.__new__(cls, machine)

    def osinfo(self):
        osinfo = {
            "flavour": "NanoBSD",
            "release": self.machine.run("cat /etc/version").strip()
            }
        osinfo.update(super(NanoBSD, self).osinfo())
        return osinfo

class Linux(RHost):
    def __new__(cls, machine):
        opsys = machine.run('if test -f /etc/default.cfg && grep -q ubnt /etc/default.cfg; then echo AirOS; elif test -f /etc/openwrt_version; then echo OpenWRT; else echo Linux; fi')
        if opsys != "Linux":
            return eval("%s(machine)" % opsys, globals(), locals())
        return super(Linux, cls).__new__(cls, machine)

    def hostname(self):
        output = self.machine.run("cat /proc/sys/kernel/hostname")
        return output.strip()

    def cpuinfo(self):
        return {
            "machine": self.machine.run("uname -m").strip(),
            "cpu": self.machine.run("egrep 'cpu model|Processor' /proc/cpuinfo | cut -d: -f2").strip(),
            "model": self.machine.run("egrep 'machine|system type|Hardware' /proc/cpuinfo | cut -d: -f2").replace("\r", "").replace("\n", "").strip(),
            }

    def interfaces(self):
        if not hasattr(self, "__ifnames__"):
            output = self.machine.run("cat /proc/net/dev").strip()
            def _ifs():
                for toks in [tokenize(l) for l in splitlines(output)[2:]]:
                    if len(toks) == 0:
                        continue
                    ifname = toks[0].split(":")[0]
                    yield ifname
            self.__ifnames__ = list(_ifs())
        return self.__ifnames__

    def ifindex(self, iface):
        output = self.machine.run("ip link show dev %s | sed 's/:.*/:/'" % iface).strip()
        return int(output.split(":")[0])
        
    def macaddr(self, iface):
        output = self.machine.run("ip link show dev %s | grep link/ether" % iface).strip()
        if not output:
            return None
        mac = tokenize(output)[1].upper()
        if len(mac.replace("0", "").replace(":", "")) == 0:
            return None
        return mac

    def llinfo(self, iface):
        llinfo = super(Linux, self).llinfo(iface)
        winfo = self.machine.run("iwconfig %s" % iface).strip()
        lines = [x.strip() for x in winfo.split("\n")]
        if len(lines) > 1:
            try:
                ssidx = lines[0].index("ESSID")
                llinfo["hwmode"] = lines[0][8:ssidx].strip()
                lines[0] = lines[0][ssidx:]
            except ValueError:
                ## sometimes ssid doesn't appear... this is very ugly
                space = lines[0].index(" ")
                lines[0] = lines[0][space:].strip()
                colon = lines[0].index(":")
                space = lines[0][:colon].rindex(" ")
                llinfo["hwmode"] = lines[0][:space].strip()
                lines[0] = lines[0][space:].strip()
            def kv(tok):
                if ":" in tok:
                    return tok.split(":", 1)
                if "=" in tok:
                    return tok.split("=", 1)
            for rest in lines:
                info = dict(kv(x.strip()) for x in rest.strip().split("  "))
                if "ESSID" in info:
                    llinfo["ssid"] = info["ESSID"].strip('"')
                if "Mode" in info:
                    llinfo["mode"] = info["Mode"]
                if "Frequency" in info:
                    llinfo["freq"] = info["Frequency"]
                if "Bit Rate" in info:
                    llinfo["bitrate"] = info["Bit Rate"]
                if "Tx-Power" in info:
                    llinfo["txpower"] = info["Tx-Power"]
                if "Signal level" in info:
                    llinfo["signal"] = info["Signal level"]
                if "Noise level" in info:
                    llinfo["noise"] = info["Noise level"]
                if "Link Quality" in info:
                    llinfo["quality"] = info["Link Quality"]
                if "Sensitivity" in info:
                    llinfo["sensitivity"] = info["Sensitivity"]
        return llinfo

    def v4addr(self, iface):
        output = self.machine.run("ip addr show dev %s | grep '^ *inet '" % iface).strip()
        def parseaddr(a):
            a = a.strip()
            if "/" not in a:
                return a + "/32"
            return a
        tokset = [tokenize(l) for l in splitlines(output)]
        return [parseaddr(toks[1]) for toks in tokset if len(toks) > 0]

    def mtu(self, iface):
        output = self.machine.run("ip link show dev %s | grep mtu | sed -e 's/.*mtu //' -e 's/ .*//'" % iface)
        return int(output.strip())

    def arptable(self, iface):
#        output = self.machine.run("ip neigh show dev %s | awk '{ print $1, $3 }'" % iface)
#        def _neighbours():
#            for line in [x.strip() for x in output.split("\n")]:
#                if len(line) == 0:
#                    continue
#                v4addr, mac = line.split(" ")
#                yield { "v4addr": v4addr, "mac": mac.upper() }
#        return list(_neighbours())
        output = self.machine.run("cat /proc/net/arp | grep %s" % iface)
        def _neighbours():
            for toks in [tokenize(l) for l in splitlines(output)]:
                if len(toks) == 0:
                    continue
                v4addr, mac = toks[0], toks[3]
                yield { "v4addr": v4addr, "mac": mac.upper() }
        return list(_neighbours())

    def v4routes(self):
        output = self.machine.run("ip route show")
        def _routes():
            for toks in [tokenize(l) for l in splitlines(output)]:
                if len(toks) < 3:
                    continue
                network, nexthop = toks[0], toks[2]
                if network == "default":
                    network = "0.0.0.0/0"
                if "/" not in network:
                    network = network + "/32"
                addr, _ = network.split("/")
                if is_bogon(addr):
                    continue
                yield {
                    "network": network,
                    "nexthop": nexthop
                    }
        return list(_routes())

    def bridges(self):
        output = self.machine.run("test -x /usr/sbin/brctl && brctl show").strip()
        if output.startswith("BusyBox"):
            return []
        lines = [x.strip() for x in output.split("\n")]
        bridges = []
        bridge = {}
        for line in lines[1:]:
            tokens = line.replace("\t", " ").split(" ")
            if len(tokens) > 1:
                if bridge:
                    bridges.append(bridge)
                bridge = {
                    "name": tokens[0],
                    "members": tokens[-1:]
                    }
            elif len(tokens) > 0:
                bridge["members"].append(tokens[0])
        if bridge:
            bridges.append(bridge)
        return bridges

    def braddrs(self, bridge):
        output = self.machine.run("brctl showmacs %(name)s" % bridge).strip()
        lines = [x.strip() for x in output.split("\n")]
        addrs = []
        for line in lines[1:]:
            tokens = [x for x in line.replace("\t", " ").split(" ") if len(x) > 0]
            addrs.append({
                    "mac":  tokens[1].upper(),
                    "port": bridge["members"][int(tokens[0])-1],
                    "local": tokens[2] == "yes"
                    })
        return addrs

class AirOS(Linux):
    def __new__(cls, machine):
        return RHost.__new__(cls, machine)

    def procs(self):
        output = self.machine.run("ps w | sed 's/S </S/' | awk '{ print $5 }'")
        return splitlines(output)[1:]

    def osinfo(self):
        airosver = self.machine.run("cat /etc/version").strip()
        osinfo = {
            "flavour":  "AirOS",
            "release": airosver
            }
        osinfo.update(super(AirOS, self).osinfo())
        return osinfo

#    def arptable(self, iface):
#        try:
#            result = super(AirOS, self).neighbours(iface)
#        except:
#            output = self.machine.run("cat /proc/net/arp | grep %s" % iface)
#            def _neighbours():
#                for toks in [tokenize(l) for l in splitlines(output)]:
#                    if len(toks) == 0:
#                        continue
#                    v4addr, mac = toks[0], toks[3]
#                    yield { "v4addr": v4addr, "mac": mac.upper() }
#            result = list(_neighbours())
#        return result

class OldAirOS(AirOS):
    def osinfo(self):
        return {
            "flavour": "AirOS",
            "opsys": self.machine.run("cat /proc/sys/kernel/ostype"),
            "osver": self.machine.run("cat /proc/sys/kernel/osrelease")
            }

    def routing_daemon(self):
        return

class OpenWRT(Linux):
    def __new__(cls, machine):
        machine.run("test ! -x /usr/sbin/ip && opkg update && opkg install ip")
        return RHost.__new__(cls, machine)

    def osinfo(self):
        ver = self.machine.run("test -f /etc/openwrt_release; echo $?").strip()
        if ver == "0":
            return self.osinfo_new()
        else:
            return self.osinfo_old()

    def osinfo_old(self):
        owrt_version = self.machine.run("cat /etc/openwrt_version").strip()
        osinfo = {
            "flavour": "OpenWRT",
            "release": owrt_version
            }
        osinfo.update(super(OpenWRT, self).osinfo())
        return osinfo

    def osinfo_new(self):
        owrt_release = self.machine.run("cat /etc/openwrt_release").strip()
        def kvp():
            for line in owrt_release.split("\n"):
                k,v = line.split("=")
                v = v.replace('"', "")
                yield (k.strip(), v.strip())
        owrt_release = dict(kvp())
        osinfo = {
            "flavour":  owrt_release["DISTRIB_ID"],
            "release":  owrt_release["DISTRIB_RELEASE"],
            "codename": owrt_release["DISTRIB_CODENAME"]
            }
        osinfo.update(super(OpenWRT, self).osinfo())
        return osinfo

def interrogate_rlogin(host, **kw):
    c = Rcmd(host=host, **kw)
    h = MetaHost(c)
    result = h.describe()
    c.logout()
    result["timestamp"] = time.time()
    return result
