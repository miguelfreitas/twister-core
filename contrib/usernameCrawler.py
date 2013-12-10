#!/usr/bin/python
#
# This sample script is a username crawler: it will obtain all known usernames
# from block chain and then try to download avatar and profiles for all of
# them. The report is shown as an html file.
#
# Downloaded data is cached in a python pickle file, so it may be executed
# again and it won't need to get everything all over again (you may run it
# from cron scripts, for example)

import sys, cPickle, time

dbFileName = "usernameCrawler.pickle"
htmlFileName = "userlist.html"
cacheTimeout = 24*3600

try:
    from bitcoinrpc.authproxy import AuthServiceProxy
except ImportError as exc:
    sys.stderr.write("Error: install python-bitcoinrpc (https://github.com/jgarzik/python-bitcoinrpc)\n")
    exit(-1)

serverUrl = "http://user:pwd@127.0.0.1:28332"
if len(sys.argv) > 1:
    serverUrl = sys.argv[1]

twister = AuthServiceProxy(serverUrl)

class User:
    avatar = ""
    fullname = ""
    location = ""
    updateTime = 0

class MyDb:
    lastBlockHash = 0

try:
    db = cPickle.load(open(dbFileName))
    nextHash = db.lastBlockHash
except:
    db = MyDb()
    db.usernames = {}
    nextHash = twister.getblockhash(0)

while True:
    block = twister.getblock(nextHash)
    db.lastBlockHash = block["hash"]
    print str(block["height"]) + "\r",
    usernames = block["usernames"]
    for u in usernames:
        if not db.usernames.has_key(u):
            db.usernames[u] = User()
    if block.has_key("nextblockhash"):
        nextHash = block["nextblockhash"]
    else:
        break

now = time.time()
for u in db.usernames.keys():
    if db.usernames[u].updateTime + cacheTimeout < now:

        print "getting avatar for", u, "..."
        d = twister.dhtget(u,"avatar","s")
        if len(d) == 1 and d[0].has_key("p") and d[0]["p"].has_key("v"):
            db.usernames[u].avatar = d[0]["p"]["v"]

        print "getting profile for", u, "..."
        d = twister.dhtget(u,"profile","s")
        if len(d) == 1 and d[0].has_key("p") and d[0]["p"].has_key("v"):
            db.usernames[u].fullname = d[0]["p"]["v"]["fullname"]
            db.usernames[u].location = d[0]["p"]["v"]["location"]

        db.usernames[u].updateTime = now

cPickle.dump(db,open(dbFileName,"w"))


from HTML import HTML
from cgi import escape
def outputHtmlUserlist(fname, db, keys):
    h = HTML()
    head = h.head("")
    with h.body(""):
        with h.table(border='1', newlines=True):
            with h.colgroup:
                h.col(span="1", style="width: 64px;")
                h.col(span="1", style="width: 130px;")
                h.col(span="1", style="width: 250px;")
                h.col(span="1", style="width: 250px;")
            with h.tr:
                h.th("avatar")
                h.th("username")
                h.th("fullname")
                h.th("location")
            for u in keys:
                with h.tr:
                    with h.td():
                        h.img('',src=escape(db.usernames[u].avatar), width="64", height="64")
                    h.td(u)
                    h.td(escape(db.usernames[u].fullname))
                    h.td(escape(db.usernames[u].location))
    open(fname, "w").write(str(h))

print "Generating", htmlFileName, "..."

keys = db.usernames.keys()
keys.sort() # sorted by username
outputHtmlUserlist(htmlFileName, db, keys)

