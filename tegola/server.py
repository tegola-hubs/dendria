from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import redirect
from storage import deref
from queries import freqinfo, getlladj
import json

log = __import__("logging").getLogger(__name__)

class TegolaRest(object):
    def __init__(self, db, mountpoint=""):
        self.db = db
        self.mountpoint = ""
        self.url_map = Map([
                Rule("%s/host/<macaddr>" % mountpoint, endpoint="host"),
                Rule("%s/host/<macaddr>/adj/link" % mountpoint, endpoint="link_adj"),
                Rule("%s/host/<macaddr>/adj/network" % mountpoint, endpoint="network_adj"),
                Rule("%s/host/<macaddr>/adj/ospf" % mountpoint, endpoint="ospf_adj"),
                Rule("%s/adj" % mountpoint, endpoint="adj"),
                Rule("%s/spectrum/" % mountpoint, endpoint="spectrum"),
                Rule("%s/spectrum/<freq>" % mountpoint, endpoint="spectrum")
                ])

    def __call__(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            return getattr(self, "on_" + endpoint)(request, **values)
        except HTTPException, e:
            return e

    def get_host(self, macaddr, templ="%s"):
        upcase = macaddr.upper()
        if macaddr != upcase:
            return redirect(self.mountpoint + templ % upcase)
        addrinfo = self.db.macaddr.find_one({"address": macaddr}, {"host": 1})
        if addrinfo is None:
            raise NotFound(macaddr)
        hostinfo = deref(self.db, addrinfo["host"])
        del hostinfo["_id"]
        return hostinfo

    def on_host(self, request, macaddr):
        hostinfo = self.get_host(macaddr, "/host/%s")
        if not isinstance(hostinfo, dict):
            return hostinfo
        if request.args.get("detail") in ("1", "true", "True"):
            data = hostinfo
        else:
            data = {
                "name": hostinfo["name"]
                }
            addrs = set()
            for iface in hostinfo.get("interfaces", []):
                for addr in iface.get("v4addr", []):
                    addrs.add(addr)
            data["v4addr"] = list(addrs)
            data["v4addr"].sort()
        return Response(json.dumps(data), mimetype="application/json")

    def on_adj(self, request):
        adjs = {}
        for host in self.db.hosts.find():
            adjs.update(getlladj(self.db, host["ident"]));
        return Response(json.dumps(adjs), mimetype="application/json")

    def on_link_adj(self, request, macaddr):
        hostinfo = self.get_host(macaddr, "/host/%s/adj/link")
        if not isinstance(hostinfo, dict):
            return hostinfo

        adjs = getlladj(self.db, macaddr)
        return Response(json.dumps(adjs), mimetype="application/json")

    def on_spectrum(self, request, freq=None):
        if freq is not None:
            freq = freq + " GHz"
        info = freqinfo(self.db, freq)
        return Response(json.dumps(info), mimetype="application/json")
