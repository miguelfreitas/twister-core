#ifndef TWISTER_H
#define TWISTER_H

#include "util.h"
#include "key.h"
#include <boost/thread.hpp>

#define LIBTORRENT_PORT_OFFSET 1000

#define USERPOST_FLAG_RT 0x01
#define USERPOST_FLAG_DM 0x02


class twister
{
public:
    twister();
};

void startSessionTorrent(boost::thread_group& threadGroup);
void stopSessionTorrent();

std::string createSignature(std::string const &strMessage, CKeyID &keyID);
std::string createSignature(std::string const &strMessage, std::string const &strUsername);
bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign);

bool acceptSignedPost(char const *data, int data_size, std::string username, int seq, std::string &errmsg, boost::uint32_t *flags);
bool validatePostNumberForUser(std::string const &username, int k);

void receivedSpamMessage(std::string const &message, std::string const &user);

int getBestHeight();

#endif // TWISTER_H
