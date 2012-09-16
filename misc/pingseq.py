import fileinput
from sys import argv
import decimal
import time
import os.path

def parse_rtt(lines):
    for line in lines:
        rtt = line.strip().split("=")[-1].split(" ")[0]
        try:
            yield decimal.Decimal(rtt)
        except decimal.InvalidOperation:
            continue

lines = fileinput.input(argv[1])
_ = lines.next() # skip first line
timestamp = int(time.mktime(time.strptime(
            lines.next().strip(),
            "%a %b %d %H:%M:%S %Z %Y")))

from pyrrd.rrd import DataSource, RRA, RRD
filename = '/tmp/test.rrd'
roundRobinArchives = []
dataSources = []
dataSource = DataSource(
    dsName="rtt", dsType="GAUGE", heartbeat=1)
dataSources.append(dataSource)
roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=1, rows=3600*24*7))
roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=60, rows=4))
roundRobinArchives.append(RRA(cf='AVERAGE', xff=0.5, steps=60, rows=12))
rrd = RRD(filename, ds=dataSources, rra=roundRobinArchives, start=timestamp-1)

if not os.path.isfile(rrd.filename):
    rrd.create()

    i = 0
    for rtt in parse_rtt(lines):
        print i, rtt
        rrd.bufferValue(timestamp+i, int(1000 * rtt))
        i += 1
        if i % 100 == 0:
            rrd.update()
    rrd.update()

from pyrrd.graph import DEF, CDEF, VDEF, LINE, AREA, GPRINT, COMMENT, Graph
comment = COMMENT("RTT from SMO to Creagan Dearga")
rttus = DEF(rrdfile=rrd.filename, vname="rttus", dsName="rtt")
rttms = CDEF(vname="rttms", rpn="%s,1000,/" % rttus.vname)
rtt = LINE(defObj=rttms, color="#2299ff", legend="RTT")
rttmax = VDEF(vname="rttmax", rpn="%s,MAXIMUM" % rttms.vname)
rttavg = VDEF(vname="rttavg", rpn="%s,AVERAGE" % rttms.vname)
rttmaxp = GPRINT(rttmax, "Maximum: %6.2lf")
rttavgp = GPRINT(rttavg, "Average: %6.2lf")

imgfile = "/tmp/testgraph.png"
g = Graph(imgfile, start=timestamp, end=timestamp+263342,
          vertical_label="ms")
g.data.extend([rttus,rttms,rtt,rttmax,rttmaxp,rttavg,rttavgp,comment])
g.write()
