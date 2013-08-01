#include "twister.h"

#include "main.h"

twister::twister()
{
}

// ===================== LIBTORRENT & DHT ===========================

#include "libtorrent/config.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/session.hpp"

#define TORRENT_DISABLE_GEO_IP
#include "libtorrent/aux_/session_impl.hpp"

using namespace libtorrent;
static session *ses;

void ThreadWaitExtIP()
{
    RenameThread("wait-extip");

    std::string ipStr;

    // wait up to 5 seconds for bitcoin to get the external IP
    for( int i = 0; i < 10; i++ ) {
        const CNetAddr paddrPeer("8.8.8.8");
        CAddress addr( GetLocalAddress(&paddrPeer) );
        if( addr.IsValid() ) {
            ipStr = addr.ToStringIP();
            break;
        }
        MilliSleep(500);
    }

    error_code ec;
    int listen_port = GetListenPort() + LIBTORRENT_PORT_OFFSET;
    std::string bind_to_interface = "";

    printf("Creating new libtorrent session ext_ip=%s port=%d\n", ipStr.c_str(), listen_port);

    ses = new session(fingerprint("LT", LIBTORRENT_VERSION_MAJOR, LIBTORRENT_VERSION_MINOR, 0, 0)
            , session::add_default_plugins
            , alert::all_categories
                    & ~(alert::dht_notification
                    + alert::progress_notification
                    + alert::debug_notification
                    + alert::stats_notification)
            , ipStr.size() ? ipStr.c_str() : NULL );

    /*
    std::vector<char> in;
    if (load_file(".ses_state", in, ec) == 0)
    {
            lazy_entry e;
            if (lazy_bdecode(&in[0], &in[0] + in.size(), e, ec) == 0)
                    ses.load_state(e);
    }
    */

    ses->listen_on(std::make_pair(listen_port, listen_port)
            , ec, bind_to_interface.c_str());
    if (ec)
    {
            fprintf(stderr, "failed to listen%s%s on ports %d-%d: %s\n"
                    , bind_to_interface.empty() ? "" : " on ", bind_to_interface.c_str()
                    , listen_port, listen_port+1, ec.message().c_str());
    }

    ses->start_dht();
    printf("libtorrent + dht started\n");
}

void startSessionTorrent(boost::thread_group& threadGroup)
{
    printf("startSessionTorrent (waiting for external IP)\n");

    threadGroup.create_thread(boost::bind(&ThreadWaitExtIP));
}

