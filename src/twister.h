#ifndef TWISTER_H
#define TWISTER_H

#include "util.h"
#include "key.h"
#include <boost/thread.hpp>
#include "json/json_spirit.h"

#define LIBTORRENT_PORT_OFFSET 1000

#define USERPOST_FLAG_RT    0x01
#define USERPOST_FLAG_DM    0x02
#define USERPOST_FLAG_FAV   0x04
#define USERPOST_FLAG_P_FAV 0x0C

//only no flagged posts and RTs are displayed at home postboard
#define USERPOST_FLAG_HOME  USERPOST_FLAG_RT

#define BLOCK_AGE_TO_EXPIRE_DHT_ENTRY (2016)   // about 2 weeks
#define BLOCK_AGE_TO_EXPIRE_DHT_POSTS (4320*2) // about 2 months
#define MAX_TIME_IN_FUTURE            (2*60*60) // same constant as in Bitcoin's main.cpp:CheckBlock()

namespace libtorrent {
    class entry;
}

class twister
{
public:
    twister();
};

void preinitSessionTorrent();
void startSessionTorrent(boost::thread_group& threadGroup);
void stopSessionTorrent();

bool getUserPubKey(std::string const &strUsername, CPubKey &pubkey, int maxHeight = -1);
std::string createSignature(std::string const &strMessage, CKeyID &keyID);
std::string createSignature(std::string const &strMessage, std::string const &strUsername);
bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign, int maxHeight = -1);

bool acceptSignedPost(char const *data, int data_size, std::string username, int seq, std::string &errmsg, boost::uint32_t *flags);
bool validatePostNumberForUser(std::string const &username, int k);
bool usernameExists(std::string const &username);

void receivedSpamMessage(std::string const &message, std::string const &user);

int getBestHeight();
bool shouldDhtResourceExpire(std::string resource, bool multi, int height);

int getDhtNodes(boost::int64_t *dht_global_nodes = NULL);

void updateSeenHashtags(std::string &message, int64_t msgTime);

// interface to dht api of the libtorrent current session
void dhtGetData(std::string const &username, std::string const &resource, bool multi, bool local);
void dhtPutData(std::string const &username, std::string const &resource, bool multi,
                libtorrent::entry const &value, std::string const &sig_user,
                boost::int64_t timeutc, int seq);
void dhtPutDataSigned(std::string const &username, std::string const &resource, bool multi,
                libtorrent::entry const &p, std::string const &sig_p, std::string const &sig_user, bool local);

json_spirit::Object getLibtorrentSessionStatus();

#endif // TWISTER_H
