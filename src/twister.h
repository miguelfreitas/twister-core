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

#endif // TWISTER_H
