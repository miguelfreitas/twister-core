#ifndef TWISTER_H
#define TWISTER_H

#include "util.h"
#include "key.h"
#include <boost/thread.hpp>

#define LIBTORRENT_PORT_OFFSET 1000

#define USERPOST_FLAG_RT 0x01
#define USERPOST_FLAG_DM 0x02

#define BLOCK_AGE_TO_EXPIRE_DHT_ENTRY (2016)   // about 2 weeks
#define BLOCK_AGE_TO_EXPIRE_DHT_POSTS (4320*2) // about 2 months


class twister
{
public:
    twister();
};

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

#endif // TWISTER_H
