twister - p2p microblogging
===========================

http://www.twister.net.co

Bitcoin Copyright (c) 2009-2013 Bitcoin Developers
libtorrent Copyright (c) 2003 - 2007, Arvid Norberg
twister Copyright (c) 2013 Miguel Freitas

What is twister?
----------------

twister is an experimental peer-to-peer microblogging software.

User registration and authentication is provided by a bitcoin-like network, so
it is completely distributed (does not depend on any central authority).

Post distribution uses kademlia DHT network and bittorrent-like swarms, both
are provided by libtorrent.

Both Bitcoin and libtorrent versions included here are highly patched and do
not interoperate with existing networks (on purpose).

License
-------

Bitcoin is released under the terms of the MIT license. See `COPYING` for more
information or see http://opensource.org/licenses/MIT.

libtorrent is released under the BSD-license.

twister specific code is released under the MIT license or BSD, you choose.
(it shouldn't matter anyway, except for the "non-endorsement clause").

Development process
-------------------

There is no development process defined yet.

Developers of either bitcoin or libtorrent are welcomed and will be granted
immediate write-access to the repository (a small retribution for
bastardizing their codebases).

Testing
-------

Some security checks are disabled (temporarily) allowing multiple clients per IP.
Therefore it is possible to run multiple twisterd instances at the same machine:

    $ twisterd -datadir=/tmp/twister1 -port=30001 -daemon -rpcuser=user -rpcpassword=pwd -rpcallowip=127.0.0.1 -rpcport=40001
    $ twisterd -datadir=/tmp/twister2 -port=30002 -daemon -rpcuser=user -rpcpassword=pwd -rpcallowip=127.0.0.1 -rpcport=40002
    $ twisterd -rpcuser=user -rpcpassword=pwd -rpcallowip=127.0.0.1 -rpcport=40001 addnode <external-ip>:30002 onetry

Note: some features (like block generation and dht put/get) do now work unless
there are at least two known nodes, like these two instances.

Wire protocol
-------------

Bitcoin and libtorrent protocol signatures have been changed on purpose to
make twister network incompatible. This avoids the so called "merge bug":

http://blog.notdot.net/2008/6/Nearly-all-DHT-implementations-vulnerable-to-merge-bug

- Bitcoin signature changed from "f9 be b4 d9" to "f0 da bb d2".
- Bitcoin port changed from 8333 to 28333.
- Torrent signature changed from "BitTorrent protocol" to "twister protocollll".
- Torrent/DHT query changed from "y" to "z"
- Torrent/DHT answer changed from "a" to "x"

Quick JSON command examples
---------------------------

To create a new user key and send it to the network:
    ./twisterd createwalletuser somebody
    ./twisterd sendnewusertransaction somebody

To create the first (1) public post:
    ./twisterd newpostmsg somebody 1 "hello world"

To add this user to the following list:
    ./twisterd follow somebody '["somebody"]'

To get the last 5 posts from user we follow:
    ./twisterd getposts 5 '[{"username":"somebody"}]'


