#!/usr/bin/python
#
# posts_sync.py example script to post from html page

import sys, cPickle, time, urllib2
from pyquery import PyQuery

reload(sys)
sys.setdefaultencoding("utf-8")

try:
    from bitcoinrpc.authproxy import AuthServiceProxy
except ImportError as exc:
    sys.stderr.write("Error: install python-bitcoinrpc (https://github.com/jgarzik/python-bitcoinrpc)\n")
    exit(-1)

### options parsing

from optparse import OptionParser
parser = OptionParser("usage: %prog [options] <page_url> <username>")
parser.add_option("-s", "--serverUrl",
                  action="store", dest="serverUrl", default="http://user:pwd@127.0.0.1:28332",
                  help="connect to specified twisterd server URL")
parser.add_option("-p", "--proxyUrl",
                  action="store", dest="proxyUrl", default="",
                  help="proxyUrl to use")
parser.add_option("-d", action="store_true", dest="dryRun",
                  help="dry-run, just report posts")

(options, args) = parser.parse_args()
if len(args) != 2:
    parser.error("incorrect number of arguments")

pageUrl = args[0]
username = args[1]

### connect to twisterd

twister = AuthServiceProxy(options.serverUrl)
lastK = -1
lastUserPost = twister.getposts(1, [{"username":username}])
for i in range(len(lastUserPost)):
    if lastUserPost[i]["userpost"]["n"] == username:
        lastK = int(lastUserPost[i]["userpost"]["k"])
        break
print username, "lastK:", lastK

### load db from previous run

dbFileName = username + ".pickle"
class MyDb:
    lastDatatime = 0
try:
    db = cPickle.load(open(dbFileName))
except:
    db = MyDb()

### setup proxy

if len(options.proxyUrl):
    proxy = urllib2.ProxyHandler({'http': options.proxyUrl,'https': options.proxyUrl})
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)

### download html content

user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.73.11 (KHTML, like Gecko) Version/7.0.1 Safari/537.73.11'
headers = { 'User-Agent' : user_agent }
req = urllib2.Request(pageUrl, headers = headers)
response = urllib2.urlopen(req)
html = response.read()
pq = PyQuery(html.decode('utf8'))

### parse html

items = pq(".StreamItem")
for i in xrange(len(items)-1,0,-1):
    item = items.eq(i)
    datatime = int(item.find("[data-time]").attr("data-time"))
    if datatime > db.lastDatatime :
        db.lastDatatime = datatime
        p = item.find("p")
        ptext = p.text()
        ptext = ptext.replace(":// ","://").replace("# ","#").replace("@ ","@")
        print "newpostmsg", username, lastK+1, ptext
        if not options.dryRun:
            try:
                twister.newpostmsg(username, lastK+1, ptext)
            except:
                pass
        lastK = lastK+1

if not options.dryRun:
    cPickle.dump(db,open(dbFileName,"w"))
