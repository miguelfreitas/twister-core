Security
================

- Encrypt user_data (which contains all DMs)

- Test wallet encrypt to see if it still works from original bitcoin implementation and what
are the implications to our code.

- Move all crypto to javascript, store only encrypted version of the privatekey (which would be
decrypted only in browser memory). getposts may obtain all DMs encrypted to browser, another
newpostmsg needs to be provided to receive posts with signature field added.


Features
================

- Store a dht resource "publickey" containing not only the public key itself but also information
needed to validate it by a lightweight client. That includes: block hash, block height and partial
merkle tree inside that block. This resource propagation cannot be sent right after user
registration for obvious reasons (no block yet, other nodes wouldn't accept the signed dht put).

- Share images

Kill bugs
================
- Rescan directmessages after importing a privatekey (importprivkey)

- Check libtorrent's limitation on the number of pieces (max_pieces in piece_picker.hpp = 1<<19)
Since post number is constrained by max of 288 posts per day in average, that means we have 5 years
to think about it (for the really heavy users).

- Implement the mention forwarding mechanism discussed in the paper so user don't need to do polling
and can also be sure to receive all mentions.

- Implement hashtag "storage-less" torrents for post distribution.

- Check stored dht values if their signature is still valid before trying to refresh another node.
Key pair might have changed and currently we receive a lot of errors from other nodes.

- save_file() must truncate file.

- Implement dht-to-torrent gateway, the "swarm" resource (so poster may not need to be member
of his own torrent)

- Estimate number of online followers by quering the "tracker" resource (implement a value within
this resource to report the number of torrent peers)

- Don't accept dht "post"+k if k violates the validatePostNumberForUser() rule.

- Implement -secdatadir= parameter to store sensitive data (wallet, dm) in a separated dir.

- Improve dhtget for the multi case so multiple responses may be joined/concatenated.

- Check pieces before sending to other peers in swarm. The issue here is that whenever
acceptSignedPost is changed to become stricter the old posts (which have been previously
accepted into torrents) may fail to pass in the new test. This causes peers to becomed
massively banned by other peers because they try to send invalid pieces.
