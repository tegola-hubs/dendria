if __name__ == '__main__':
    import logging
    from sys import argv, exit
    from interrogate import interrogate
    from pprint import pprint
    from storage import pkey_check, mergedict

    logging.basicConfig(level=logging.INFO)

#    from rlogin import Rcmd, MetaHost
#    c = Rcmd(host=argv[1], username=argv[3], password=argv[4])
#    h = MetaHost(c)
#    pprint(h.router_info())
#    c.logout()
#    exit(0)

    descr = interrogate(argv[1], community=argv[2], username=argv[3], password=argv[4])
#    pprint(descr)
    ident = pkey_check(descr)
    print "identifier:", ident

    import redis
    import json

    r = redis.Redis()
    for k,v in descr.items():
        r.hset(k, ident, json.dumps(v))
    merged = mergedict(list(descr.values()))

    r.hset("hosts", ident, merged)
    for addr in [x.get("mac") for x in merged["interfaces"]]:
        if addr is None:
            continue
        r.hset("macaddrs", addr, ident)


