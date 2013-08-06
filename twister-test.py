#!/usr/bin/python

import os,sys

twister = "../twister-qt-build-desktop/twisterd"

cmd = sys.argv[1]
n   = int(sys.argv[2])

datadir = "/tmp/twister%d" % n
port = "%d" % (30000+n)
rpcport = "%d" % (40000+n)
if (n!=1):
    addnode="-addnode=127.0.0.1:30001"
else:
    addnode=""

if cmd == "start":
    try:
        os.mkdir(datadir)
    except:
        pass
    os.system( twister + " -datadir=" + datadir +
               " -port=" + port + " -daemon" +
               " -rpcuser=user -rpcpassword=pwd -rpcport=" + rpcport +
               " " + addnode )

if cmd == "cmd":
    if( len(sys.argv) < 4 ):
        print "missing command (try help)"
        sys.exit(-1)
    parms = ""
    for i in xrange(3,len(sys.argv)):
        parms += ' "' + sys.argv[i] + '"'
    os.system( twister + " -rpcuser=user -rpcpassword=pwd -rpcport=" + rpcport + parms )

