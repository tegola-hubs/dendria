from utils import flatten

log = __import__("logging").getLogger(__name__)

def get_db(args=None):
    import pymongo
    if args is not None and args.dbhost:
        host = args.dbhost
    else:
        host = "127.0.0.1"
    if args is not None and args.dbport:
        port = args.dbport
    else:
        port = 27017
    if args is not None and args.dbname:
        dbname = args.dbname
    else:
        dbname = "tegola"
    log.debug("Connecting to the MongoDB database")
    conn = pymongo.Connection(host, port)
    return getattr(conn, dbname)

class PKeyError(Exception):
    pass

def pkey(descr):
    if not isinstance(descr, dict):
        raise ValueError("Not a dictionary: %s" % descr)
    interfaces = descr.get("interfaces", None)
    if interfaces is None:
        raise ValueError("No interfaces: %s" % descr)
    indices = list( (int(x["ifindex"]), x) for x in interfaces )
    indices.sort(lambda x,y: cmp(x[0], y[0]))
    for _, iface in indices:
        mac = iface.get("mac", None)
        if mac is not None:
            return mac
    raise ValueError("Could not determine physical address: %s" % descr)

def pkey_check(multidescr):
    keys = dict( (k,pkey(v)) for k,v in multidescr.items() )
    pkeys = set(keys.values())
    if len(pkeys) == 0:
        raise PKeyError("Could not find any keys")
    if len(pkeys) > 1:
        raise PKeyError("Inconsistent keys: %s" % pkeys)
    return pkeys.pop()

class MergeError(Exception):
    pass

def mergedict(dicts):
    result = {}
    keys = set(flatten([d.keys() for d in dicts]))
    for k in keys:
        vals = [v for v in [d.get(k) for d in dicts] if v]
        if len(vals) == 0:
            continue
        if k in ("_id", "timestamp"):
            continue
        if isinstance(vals[0], dict):
            result[k] = mergedict(vals)
        elif isinstance(vals[0], (str, unicode, int, bool, long)):
            v = set(flatten(vals))
            if len(v) == 1:
                result[k] = v.pop()
            else:
                result[k] = list(v)
        elif isinstance(vals[0], (list, tuple)) and isinstance(vals[0][0], (str, unicode, int, bool)):
            result[k] = list(set(flatten(vals)))
        elif k == "interfaces":
            result[k] = mergedict_bykeys(vals, "ifindex")
        elif k == "arp":
            result[k] = mergedict_bykeys(vals, "mac", "v4addr")
        elif k == "neighbours":
            result[k] = mergedict_bykeys(vals, "v4addr")
        elif k == "v4routes":
            result[k] = mergedict_bykeys(vals, "network")
        elif k == "bridges":
            result[k] = mergedict_bykeys(vals, "name")
        elif k == "addresses":
            result[k] = mergedict_bykeys(vals, "mac")
        else:
            raise MergeError("unhandled key: %s" % k)
    return result

def mergedict_bykeys(l, *keys):
    indexed = {}
    for dlist in l:
        for desc in dlist:
            pkey = tuple(desc.get(k) for k in keys)
            indexed.setdefault(pkey, []).append(desc)
    result = []
    for v in indexed.values():
        result.append(mergedict(v))
    return result

def prunedict(d, *keys):
    for k in keys:
        del d[k]
    return d

def deref(db, ref):
    collection = getattr(db, ref.collection)
    return collection.find_one({"_id": ref.id})
