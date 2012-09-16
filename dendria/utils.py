import ipaddress as ip

def unpackmac(m):
    if m is not None:
        return ":".join("%02X" % ord(c) for c in m)

def is_bogon(s):
    addr = ip.ip_address(s)
    if addr in ip.ip_network('127.0.0.0/8'):
        return True
    if addr in ip.ip_network('192.0.2.0/24'):
        return True
    if addr in ip.ip_network('169.254.0.0/16'):
        return True
    return False

def splitlines(buf):
    return [l.strip() for l in buf.split("\n")]

def tokenize(line):
    return [tok for tok in line.replace("\t", " ").split(" ") if tok != ""]

def loglines(f, buf):
    for line in buf.rstrip().split("\n"):
        f(buf)

def flatten(l, ltypes=(list, tuple)):
    ltype = type(l)
    l = list(l)
    i = 0
    while i < len(l):
        while isinstance(l[i], ltypes):
            if not l[i]:
                l.pop(i)
                i -= 1
                break
            else:
                l[i:i + 1] = l[i]
        i += 1
    return ltype(l)
