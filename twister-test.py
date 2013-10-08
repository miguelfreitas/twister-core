#!/usr/bin/python

import os,sys,time

ext_ip  = os.environ['EXTIP']
twister = "../twister-qt-build-desktop/twisterd"

cmd = sys.argv[1]
n   = int(sys.argv[2])

datadir = "/tmp/twister%d" % n
port = "%d" % (30000+n)
rpcport = "%d" % (40000+n)
rpcline = " -genproclimit=1 -rpcuser=user -rpcpassword=pwd -rpcallowip=127.0.0.1 -rpcport="
rpccfg = rpcline + rpcport
rpccfg1 = rpcline + "40001"


if cmd == "start":
    try:
        os.mkdir(datadir)
    except:
        pass
    os.system( twister + " -datadir=" + datadir +
               " -port=" + port + " -daemon" +
               rpccfg )
    if( n != 1):
        time.sleep(1)
        os.system( twister + rpccfg1 + " addnode " + ext_ip + ":" + port + " onetry" )
        os.system( twister + rpccfg + " addnode " + ext_ip + ":30001 onetry" )

if cmd == "cmd":
    if( len(sys.argv) < 4 ):
        print "missing command (try help)"
        sys.exit(-1)
    parms = ""
    for i in xrange(3,len(sys.argv)):
        parms += " '" + sys.argv[i] + "'"
    os.system( twister + rpccfg + parms )

