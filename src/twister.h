#ifndef TWISTER_H
#define TWISTER_H

#include "util.h"
#include <boost/thread.hpp>

#define LIBTORRENT_PORT_OFFSET 1000

class twister
{
public:
    twister();
};

void startSessionTorrent(boost::thread_group& threadGroup);
void stopSessionTorrent();

std::string createSignature(std::string const &strMessage, std::string const &strUsername);
bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign);

bool acceptSignedPost(char const *data, int data_size, std::string username, int seq);
bool validatePostNumberForUser(std::string const &username, int k);

int getBestHeight();

#endif // TWISTER_H
