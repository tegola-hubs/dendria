from snmp import interrogate_snmp
from rlogin import interrogate_rlogin
from traceback import format_exc
log = __import__("logging").getLogger(__name__)

__all__ = ['interrogate']

def interrogate(host, **kw):
    result = {}
    try:
        result["snmp"] = interrogate_snmp(host, **kw)
    except Exception, e:
        log.warning(str(e) + "\n" + format_exc())
    try:
        result["rlogin"] = interrogate_rlogin(host, **kw)
    except Exception, e:
        log.warning(str(e) + "\n" + format_exc())
    return result

