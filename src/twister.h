#ifndef TWISTER_H
#define TWISTER_H

#include <boost/thread.hpp>

#define LIBTORRENT_PORT_OFFSET 1000

class twister
{
public:
    twister();
};

void startSessionTorrent(boost::thread_group& threadGroup);
void stopSessionTorrent();

std::string createSignature(std::string &strMessage, std::string &strUsername);
bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign);


#endif // TWISTER_H
