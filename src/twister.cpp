#include "twister.h"

#include "twister_utils.h"
#include "dhtproxy.h"

#include "main.h"
#include "init.h"
#include "bitcoinrpc.h"
#include "txdb.h"
#include "utf8core.h"
#include "libtorrent/peer_info.hpp"

using namespace json_spirit;
using namespace std;

#include <boost/shared_ptr.hpp>
#include <boost/filesystem.hpp>
#ifdef HAVE_BOOST_LOCALE
  #include <boost/locale.hpp>
#endif
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <time.h>

twister::twister()
{
}

// ===================== LIBTORRENT & DHT ===========================

#include "libtorrent/config.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/alert_types.hpp"

#define TORRENT_DISABLE_GEO_IP
#include "libtorrent/aux_/session_impl.hpp"

#define DEBUG_ACCEPT_POST 1
//#define DEBUG_EXPIRE_DHT_ITEM 1
//#define DEBUG_MAINTAIN_DHT_NODES 1
//#define DEBUG_NEIGHBOR_TORRENT 1

using namespace libtorrent;
static boost::shared_ptr<session> m_ses;
static bool m_shuttingDownSession = false;
static bool m_usingProxy;
static int num_outstanding_resume_data;

static CCriticalSection cs_dhtgetMap;
static map<sha1_hash, std::list<alert_manager*> > m_dhtgetMap;

static CCriticalSection cs_twister;
static map<std::string, bool> m_specialResources;
enum ExpireResType { SimpleNoExpire, NumberedNoExpire, PostNoExpireRecent };
static map<std::string, ExpireResType> m_noExpireResources;
static map<std::string, torrent_handle> m_userTorrent;
static map<std::string, torrent_handle> m_peekTorrent;
static boost::scoped_ptr<CLevelDB> m_swarmDb;
static int m_threadsToJoin;

static CCriticalSection cs_spamMsg;
static std::string m_preferredSpamLang = "[en]";
static std::string m_receivedSpamMsgStr;
static std::string m_receivedSpamUserStr;
static int         m_receivedSpamHeight;
static int64       m_lastSpamTime = 0;
static std::map<std::string,UserData> m_users;
static std::map<std::string,GroupChat> m_groups;

static CCriticalSection cs_seenHashtags;
static std::map<std::string,double> m_seenHashtags;

static bool generateOpt = 0;
static int genproclimit = 1;

const double hashtagHalfLife      = 8*60*60;    // Halve votes within 8 hours (sec)
const double hashtagExpiration    = 7*24*60*60; // Remove a hashtag from the list after ~ hashtagExpiration*count (sec)
const int    hashtagTimerInterval = 60;         // Timer interval (sec)

const double hashtagAgingFactor   = pow(0.5, hashtagTimerInterval/hashtagHalfLife);
const double hashtagCriticalValue = pow(0.5, hashtagExpiration/hashtagHalfLife);

const char*  msgTokensDelimiter  = " \n\t.,:/?!;'\"()[]{}*";

class SimpleThreadCounter {
public:
    SimpleThreadCounter(CCriticalSection *lock, int *counter, const char *name) :
        m_lock(lock), m_counter(counter), m_name(name) {
        RenameThread(m_name);
        LOCK(*m_lock);
        (*m_counter)++;
    }
    ~SimpleThreadCounter() {
        printf("%s thread exit\n", m_name);
        LOCK(*m_lock);
        (*m_counter)--;
    }
private:
    CCriticalSection *m_lock;
    int *m_counter;
    const char *m_name;
};

#define USER_DATA_FILE "user_data"
#define GLOBAL_DATA_FILE "global_data"
#define GROUP_DATA_FILE "group_data"

void dhtgetMapAdd(sha1_hash &ih, alert_manager *am)
{
    LOCK(cs_dhtgetMap);
    m_dhtgetMap[ih].push_back(am);
}

void dhtgetMapRemove(sha1_hash &ih, alert_manager *am)
{
    LOCK(cs_dhtgetMap);
    std::map<sha1_hash, std::list<alert_manager*> >::iterator mi = m_dhtgetMap.find(ih);
    if( mi != m_dhtgetMap.end() ) {
        std::list<alert_manager *> &amList = (*mi).second;
        amList.remove(am);
        if( !amList.size() ) {
            m_dhtgetMap.erase(ih);
        }
    }
}

void dhtgetMapPost(sha1_hash &ih, const alert &a)
{
    LOCK(cs_dhtgetMap);
    std::map<sha1_hash, std::list<alert_manager*> >::iterator mi = m_dhtgetMap.find(ih);
    if( mi != m_dhtgetMap.end() ) {
        std::list<alert_manager *> &amList = (*mi).second;
        BOOST_FOREACH(alert_manager *am, amList) {
            am->post_alert(a);
        }
    }
}

torrent_handle startTorrentUser(std::string const &username, bool following, int peek_single_piece=-1)
{
    bool userInTxDb = usernameExists(username); // keep this outside cs_twister to avoid deadlock
    boost::shared_ptr<session> ses(m_ses);
    if( !userInTxDb || !ses )
        return torrent_handle();
    torrent_handle h;

    LOCK(cs_twister);
    if( m_peekTorrent.count(username) ) {
        /* multiple paralel peek piece operations per torrent not
         * currently supported. return invalid handle for subsequent
         * requests, until current operation completes and torrent
         * is freed. */
         return torrent_handle();
    }

    if( !m_userTorrent.count(username) || peek_single_piece >= 0 ) {
        sha1_hash ih = dhtTargetHash(username, "tracker", "m");

        printf("adding torrent for [%s,tracker]\n", username.c_str());
        add_torrent_params tparams;
        tparams.info_hash = ih;
        tparams.name = username;
        boost::filesystem::path torrentPath = GetDataDir() / "swarm";
        tparams.save_path= torrentPath.string();
        tparams.peek_single_piece = peek_single_piece;
        boost::system::error_code ec;
        boost::filesystem::create_directory(torrentPath, ec);
        if (ec) {
            fprintf(stderr, "failed to create directory '%s': %s\n", torrentPath.string().c_str(), ec.message().c_str());
        }
        std::string filename = combine_path(tparams.save_path, to_hex(ih.to_string()) + ".resume");
        load_file(filename.c_str(), tparams.resume_data);

        h = ses->add_torrent(tparams);
        if( peek_single_piece < 0 ) {
            m_userTorrent[username] = h;
        } else {
            m_peekTorrent[username] = h;
        }
        if( !following ) {
            h.auto_managed(true);
        }
        h.force_dht_announce();
    } else {
        h = m_userTorrent[username];
    }
    if( following ) {
        h.set_following(true);
        h.auto_managed(false);
        h.resume();
    }
    return h;
}

torrent_handle getTorrentUser(std::string const &username)
{
    LOCK(cs_twister);
    if( m_userTorrent.count(username) )
        return m_userTorrent[username];
    else
        return torrent_handle();
}

int torrentLastHave(std::string const &username)
{
    torrent_handle h = getTorrentUser(username);
    if( !h.is_valid() )
        return -1;

    torrent_status status = h.status();
    return status.last_have;
}

int torrentNumPieces(std::string const &username)
{
    torrent_handle h = getTorrentUser(username);
    if( !h.is_valid() )
        return -1;

    torrent_status status = h.status();
    return status.num_pieces;
}

int saveGlobalData(std::string const& filename)
{
    LOCK(cs_twister);
    entry globalDict;

    globalDict["preferredSpamLang"] = m_preferredSpamLang;
    globalDict["receivedSpamMsg"]   = m_receivedSpamMsgStr;
    globalDict["receivedSpamUser"]  = m_receivedSpamUserStr;
    globalDict["receivedSpamHeight"]= m_receivedSpamHeight;
    globalDict["lastSpamTime"]      = m_lastSpamTime;

    entry spams(entry::list_t);
    {
        LOCK(cs_spamMessages);
        BOOST_FOREACH(string msg, spamMessages)
            spams.list().push_back(msg);
    }
    globalDict["sendSpamMsg"]       = spams;
    globalDict["sendSpamUser"]      = strSpamUser;
    globalDict["generate"]          = GetBoolArg("-gen", false);
    int genproclimit = GetArg("-genproclimit", -1);
    if( genproclimit > 0 )
        globalDict["genproclimit"]  = genproclimit;
    globalDict["portUsedLastTime"]  = GetListenPort();

    std::vector<char> buf;
    bencode(std::back_inserter(buf), globalDict);
    return save_file(filename, buf);
}

int loadGlobalData(std::string const& filename)
{
    LOCK(cs_twister);
    std::vector<char> in;
    if (load_file(filename, in) == 0) {
        lazy_entry userDict;
        libtorrent::error_code ec;
        if (lazy_bdecode(&in[0], &in[0] + in.size(), userDict, ec) == 0) {
            if( userDict.type() != lazy_entry::dict_t ) goto data_error;

            m_preferredSpamLang   = userDict.dict_find_string_value("preferredSpamLang");
            m_receivedSpamMsgStr  = userDict.dict_find_string_value("receivedSpamMsg");
            m_receivedSpamUserStr = userDict.dict_find_string_value("receivedSpamUser");
            m_receivedSpamHeight  = userDict.dict_find_int_value("receivedSpamHeight");
            m_lastSpamTime        = userDict.dict_find_int_value("lastSpamTime");

            const lazy_entry *sendSpamMsg    = userDict.dict_find_list("sendSpamMsg");
            if (sendSpamMsg)
            {
                LOCK(cs_spamMessages);
                for (int i = 0; i < sendSpamMsg->list_size(); i++)
                    spamMessages.push_back(sendSpamMsg->list_string_value_at(i));
            }
            else
            {
                string strSSM = userDict.dict_find_string_value("sendSpamMsg");
                LOCK(cs_spamMessages);
                if(strSSM.size() && strSSM != strSpamMessage)
                    spamMessages.push_back(strSSM);
            }

            string sendSpamUser   = userDict.dict_find_string_value("sendSpamUser");
            if( sendSpamUser.size() ) strSpamUser = sendSpamUser;
            generateOpt           = userDict.dict_find_int_value("generate");
            genproclimit          = userDict.dict_find_int_value("genproclimit");
            portUsedLastTime      = userDict.dict_find_int_value("portUsedLastTime");

            return 0;
        }
    }
    return -1;

data_error:
    printf("loadGlobalData: unexpected bencode type - global_data corrupt!\n");
    return -2;
}

void ThreadWaitExtIP()
{
    SimpleThreadCounter threadCounter(&cs_twister, &m_threadsToJoin, "wait-extip");

    std::string ipStr;
    // wait up to 10 seconds for bitcoin to get the external IP
    for( int i = 0; i < 20; i++ ) {
        const CNetAddr paddrPeer("8.8.8.8");
        CAddress addr( GetLocalAddress(&paddrPeer) );
        if( addr.IsValid() ) {
            ipStr = addr.ToStringIP();
            break;
        }
        MilliSleep(500);
    }

    libtorrent::error_code ec; // libtorrent::error_code == boost::system::error_code

    boost::filesystem::path swarmDbPath = GetDataDir() / "swarm" / "db";
    boost::filesystem::create_directories(swarmDbPath, ec);
    if (ec) {
        fprintf(stderr, "failed to create directory '%s': %s\n", swarmDbPath.string().c_str(), ec.message().c_str());
    }
    m_swarmDb.reset(new CLevelDB(swarmDbPath.string(), 256*1024, false, false));

    int listen_port = GetListenPort() + LIBTORRENT_PORT_OFFSET;
    std::string bind_to_interface = "";
    proxyType proxyInfoOut;
    m_usingProxy = GetProxy(NET_IPV4, proxyInfoOut);

    printf("Creating new libtorrent session ext_ip=%s port=%d proxy=%s\n",
           ipStr.c_str(), !m_usingProxy ? listen_port : 0,
           m_usingProxy ? proxyInfoOut.first.ToStringIPPort().c_str() : "");

    m_ses.reset(new session(*m_swarmDb, fingerprint("TW", LIBTORRENT_VERSION_MAJOR, LIBTORRENT_VERSION_MINOR, 0, 0)
            , session::add_default_plugins
            , alert::dht_notification | alert::status_notification
            , ipStr.size() ? ipStr.c_str() : NULL
            , !m_usingProxy ? std::make_pair(listen_port, listen_port) : std::make_pair(0, 0) ));
    boost::shared_ptr<session> ses(m_ses);

    if( m_usingProxy ) {
        proxy_settings proxy;
        proxy.hostname = proxyInfoOut.first.ToStringIP();
        proxy.port     = proxyInfoOut.first.GetPort();
        proxy.type     = HaveNameProxy() ? proxy_settings::socks5 :
                                           proxy_settings::socks4;
        ses->set_proxy(proxy);
    }

    // session will be paused until we have an up-to-date blockchain
    ses->pause();

    std::vector<char> in;
    boost::filesystem::path sesStatePath = GetDataDir() / "ses_state";
    if (load_file(sesStatePath.string(), in) == 0)
    {
            lazy_entry e;
            if (lazy_bdecode(&in[0], &in[0] + in.size(), e, ec) == 0)
                    ses->load_state(e);
    }

    if( !m_usingProxy ) {
        if( GetBoolArg("-upnp", true) ) {
            ses->start_upnp();
            ses->start_natpmp();
        }

        ses->listen_on(std::make_pair(listen_port, listen_port)
                       , ec, bind_to_interface.c_str());
        if (ec)
        {
            fprintf(stderr, "failed to listen%s%s on ports %d-%d: %s\n"
                    , bind_to_interface.empty() ? "" : " on ", bind_to_interface.c_str()
                    , listen_port, listen_port+1, ec.message().c_str());
        }

        dht_settings dhts;
        // settings to test local connections
        //dhts.restrict_routing_ips = false;
        //dhts.restrict_search_ips = false;
        ses->set_dht_settings(dhts);

        if( !DhtProxy::fEnabled ) {
            ses->start_dht();
        } else {
            ses->stop_dht();
        }
    }

    session_settings settings("twisterd/"+FormatFullVersion());
    // settings to test local connections
    settings.allow_multiple_connections_per_ip = GetBoolArg("-multiconnperip", false);
    //settings.enable_outgoing_utp = false; // (false to see connections in netstat)
    //settings.dht_announce_interval = 60; // test
    //settings.min_announce_interval = 60; // test
    if( !m_usingProxy ) {
        settings.anonymous_mode = false; // (false => send peer_id, avoid connecting to itself)
    } else {
        settings.anonymous_mode = true;
        settings.force_proxy = true; // DHT won't work
    }
    // disable read cache => there is still some bug due to twister piece size changes
    settings.use_read_cache = false;
    settings.cache_size = 0;

    // more connections. less memory per connection.
    settings.connections_limit = 800;
    settings.recv_socket_buffer_size = 16*1024;
    settings.send_socket_buffer_size = 16*1024;
    settings.max_peerlist_size = 1000;
    settings.max_paused_peerlist_size = 1000;
    // reduce timeouts
    settings.peer_timeout = 60;
    settings.request_timeout = 20;
    // more torrents in auto manager
    settings.active_downloads     = 20;
    settings.active_limit         = 25;
    settings.unchoke_slots_limit  = 20;
    settings.auto_manage_interval = 30;
    // dht upload rate limit (enforced only for non-locally generated requests)
    // limits: DHT replies, refreshes of stored items, checking for status/tracker and proxy server.
    settings.dht_upload_rate_limit = 16000;
    ses->set_settings(settings);

    printf("libtorrent + dht started\n");

    // wait up to 10 seconds for dht nodes to be set
    for( int i = 0; i < 10; i++ ) {
        MilliSleep(1000);
        session_status ss = ses->status();
        if( ss.dht_nodes )
            break;
    }

    if( generateOpt ) {
        Array params;
        params.push_back( generateOpt );
        if( genproclimit > 0 )
            params.push_back( genproclimit );
        setgenerate(params, false);
    }

    std::set<std::string> torrentsToStart;
    {
        LOCK(cs_twister);
        boost::filesystem::path userDataPath = GetDataDir() / USER_DATA_FILE;
        loadUserData(userDataPath.string(), m_users);
        printf("loaded user_data for %zd users\n", m_users.size());

        boost::filesystem::path groupDataPath = GetDataDir() / GROUP_DATA_FILE;
        loadGroupData(groupDataPath.string(), m_groups);

        // add all user torrents to a std::set (all m_following)
        std::map<std::string,UserData>::const_iterator i;
        for (i = m_users.begin(); i != m_users.end(); ++i) {
            UserData const &data = i->second;
            BOOST_FOREACH(string username, data.m_following) {
                torrentsToStart.insert(username);
            }
        }

        // add torrents from groups
        std::map<std::string,GroupChat>::const_iterator j;
        for (j = m_groups.begin(); j != m_groups.end(); ++j) {
            GroupChat const &data = j->second;
            BOOST_FOREACH(string username, data.m_members) {
                torrentsToStart.insert(username);
            }
        }

    }
    // now restart the user torrents
    BOOST_FOREACH(string username, torrentsToStart) {
        startTorrentUser(username, true);
    }
}

bool isBlockChainUptodate() {
    if( !pindexBest )
        return false;
    return (pindexBest->GetBlockTime() > GetTime() - 24 * 60 * 60);
}

bool yes(libtorrent::torrent_status const&)
{ return true; }

void saveTorrentResumeData()
{
    boost::shared_ptr<session> ses(m_ses);
    if( ses ){
            printf("saving resume data\n");
            std::vector<torrent_status> temp;
            ses->get_torrent_status(&temp, &yes, 0);
            for (std::vector<torrent_status>::iterator i = temp.begin();
                i != temp.end(); ++i)
            {
                torrent_status& st = *i;
                if (!st.handle.is_valid())
                {
                    printf("  skipping, invalid handle\n");
                    continue;
                }
                if (!st.has_metadata)
                {
                    printf("  skipping %s, no metadata\n", st.name.c_str());
                    continue;
                }
                if (!st.need_save_resume)
                {
                    printf("  skipping %s, resume file up-to-date\n", st.name.c_str());
                    continue;
                }

                // save_resume_data will generate an alert when it's done
                st.handle.save_resume_data();
                ++num_outstanding_resume_data;
            }
    }
}

void lockAndSaveUserData()
{
    LOCK(cs_twister);
    if( m_users.size() ) {
        printf("saving user_data (followers and DMs)...\n");
        boost::filesystem::path userDataPath = GetDataDir() / USER_DATA_FILE;
        saveUserData(userDataPath.string(), m_users);
    }
    if( m_groups.size() ) {
        boost::filesystem::path groupDataPath = GetDataDir() / GROUP_DATA_FILE;
        saveGroupData(groupDataPath.string(), m_groups);
    }
}

int getDhtNodes(boost::int64_t *dht_global_nodes)
{
    int dhtNodes = 0;

    if( dht_global_nodes )
        *dht_global_nodes = 0;

    if( !DhtProxy::fEnabled ) {
        boost::shared_ptr<session> ses(m_ses);
        if( ses ) {
            session_status ss = ses->status();
            if( dht_global_nodes )
                *dht_global_nodes = ss.dht_global_nodes;
            dhtNodes = ss.dht_nodes;
        }
    } else {
        LOCK(cs_vNodes);
        DhtProxy::getRandomDhtProxies(&dhtNodes);
    }
    return dhtNodes;
}

void torrentManualTrackerUpdate(const std::string &username)
{
    printf("torrentManualTrackerUpdate: updating torrent '%s'\n",
            username.c_str());

    Array params;
    params.push_back(username);
    params.push_back("tracker");
    params.push_back("m");
    Array res = dhtget(params, false).get_array();
    if( !res.size() ) {
        printf("torrentManualTrackerUpdate: no tracker response for torrent '%s'\n",
                username.c_str());
    } else {
        torrent_handle h = getTorrentUser(username);
        for( size_t i = 0; i < res.size(); i++ ) {
            if( res.at(i).type() != obj_type )
                continue;
            Object resDict = res.at(i).get_obj();

            BOOST_FOREACH(const Pair& item, resDict) {
                if( item.name_ == "p" && item.value_.type() == obj_type ) {
                    Object pDict = item.value_.get_obj();
                    BOOST_FOREACH(const Pair& pitem, pDict) {
                        if( pitem.name_ == "v" && pitem.value_.type() == obj_type ) {
                            Object vDict = pitem.value_.get_obj();
                            BOOST_FOREACH(const Pair& vitem, vDict) {
                                if( vitem.name_ == "values" && vitem.value_.type() == array_type ) {
                                    Array values = vitem.value_.get_array();
                                    printf("torrentManualTrackerUpdate: tracker for '%s' returned %zd values\n",
                                           username.c_str(), values.size());
                                    for( size_t j = 0; j < values.size(); j++ ) {
                                        if( values.at(j).type() != str_type )
                                            continue;
                                        size_t inSize = values.at(j).get_str().size();
                                        char const* in = values.at(j).get_str().data();
                                        tcp::endpoint ep;
                                        if( inSize == 6 ) {
                                            ep = libtorrent::detail::read_v4_endpoint<tcp::endpoint>(in);
                                        }
#if TORRENT_USE_IPV6
                                        else if ( inSize == 18 ) {
                                            ep = libtorrent::detail::read_v6_endpoint<tcp::endpoint>(in);
                                        }
#endif
                                        else {
                                            continue;
                                        }
                                        h.connect_peer(ep);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void ThreadMaintainDHTNodes()
{
    SimpleThreadCounter threadCounter(&cs_twister, &m_threadsToJoin, "maintain-dht-nodes");

    while(!m_ses && !m_shuttingDownSession) {
        MilliSleep(200);
    }

    int64 lastSaveResumeTime = GetTime();
    int64 lastManualTrackerUpdate = GetTime();
    int   lastTotalNodesCandidates = 0;

    while(m_ses && !m_shuttingDownSession) {
        boost::shared_ptr<session> ses(m_ses);

        session_status ss = ses->status();
        int dht_nodes = ss.dht_nodes;
        bool nodesAdded = false;
        int vNodesSize = 0;
        {
            LOCK(cs_vNodes);
            vNodesSize = vNodes.size();
        }

        if( !ses->is_paused() && !DhtProxy::fEnabled ) {
            vector<CAddress> vAddr = addrman.GetAddr();
            int totalNodesCandidates = (int)(vNodesSize + vAddr.size());
            if( ((!dht_nodes && totalNodesCandidates) ||
                 (dht_nodes < 5 && totalNodesCandidates > 10)) &&
                 !m_usingProxy &&
                 totalNodesCandidates != lastTotalNodesCandidates) {
                lastTotalNodesCandidates = totalNodesCandidates;
                printf("ThreadMaintainDHTNodes: too few dht_nodes, trying to add some...\n");
                BOOST_FOREACH(const CAddress &a, vAddr) {
                    std::string addr = a.ToStringIP();
                    int port = a.GetPort() + LIBTORRENT_PORT_OFFSET;
#ifdef DEBUG_MAINTAIN_DHT_NODES
                    printf("Adding dht node (addrman) %s:%d\n", addr.c_str(), port);
#endif
                    ses->add_dht_node(std::pair<std::string, int>(addr, port));
                    nodesAdded = true;
                }
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes) {
                    // if !fInbound we created this connection so ip is reachable.
                    // we can't use port number of inbound connection, so try standard port.
                    // only use inbound as last resort (if dht_nodes empty)
                    if( !pnode->fInbound || !dht_nodes ) {
                        std::string addr = pnode->addr.ToStringIP();
                        int port = (!pnode->fInbound) ? pnode->addr.GetPort() : Params().GetDefaultPort();
                        port += LIBTORRENT_PORT_OFFSET;

#ifdef DEBUG_MAINTAIN_DHT_NODES
                        printf("Adding dht node (%sbound) %s:%d\n", (!pnode->fInbound) ? "out" : "in",
                               addr.c_str(), port);
#endif
                        ses->add_dht_node(std::pair<std::string, int>(addr, port));
                        nodesAdded = true;
                    }
                }
            }
        }

        if( ses->is_paused() ) {
            if( vNodesSize && isBlockChainUptodate() ) {
                printf("BlockChain is now up-to-date: unpausing libtorrent session\n");
                ses->resume();
            }
        } else {
            if( !vNodesSize || !isBlockChainUptodate() ) {
                printf("Outdated BlockChain detected: pausing libtorrent session\n");
                ses->pause();
            }
        }

        if( nodesAdded ) {
            MilliSleep(2000);
            ss = ses->status();
            if( ss.dht_nodes > dht_nodes ) {
                // new nodes were added to dht: force updating peers from dht so torrents may start faster
                LOCK(cs_twister);
                BOOST_FOREACH(const PAIRTYPE(std::string, torrent_handle)& item, m_userTorrent) {
                    item.second.force_dht_announce();
                }
            }
        }

        if( !vNodesSize && dht_nodes ) {
            printf("ThreadMaintainDHTNodes: registration network is down, trying to add nodes from DHT...\n");
            for( size_t i = 0; i < ss.dht_routing_table.size(); i++ ) {
                dht_routing_bucket &bucket = ss.dht_routing_table[i];
                if( bucket.num_nodes ) {
#ifdef DEBUG_MAINTAIN_DHT_NODES
                    printf("DHT bucket [%zd] random node = %s:%d\n", i,
                           bucket.random_node.address().to_string().c_str(),
                           bucket.random_node.port);
#endif
                    char nodeStr[64];
                    sprintf(nodeStr,"%s:%d", bucket.random_node.address().to_string().c_str(),
                            bucket.random_node.port - LIBTORRENT_PORT_OFFSET);
                    CAddress addr;
                    ConnectNode(addr, nodeStr);
                }
            }
        }

        // if dhtproxy is enabled we may need to manually obtain peer lists from trackers
        if( DhtProxy::fEnabled && !ses->is_paused() &&
            GetTime() > lastManualTrackerUpdate + 60 ) {
            list<string> activeTorrents;
            {
                LOCK(cs_twister);
                BOOST_FOREACH(const PAIRTYPE(std::string, torrent_handle)& item, m_userTorrent) {
                    activeTorrents.push_back(item.first);
                }
            }

            BOOST_FOREACH(const std::string &username, activeTorrents) {
                if( m_shuttingDownSession )
                    break;
                torrent_handle h = getTorrentUser(username);
                if( h.is_valid() ) {
                    torrent_status status = h.status();
                    if( status.state == torrent_status::downloading &&
                        status.connect_candidates < 5 ) {
                        torrentManualTrackerUpdate(username);
                    }
                }
            }
            lastManualTrackerUpdate = GetTime();
        }

        // periodically save resume data. if daemon crashes we don't lose everything.
        if( GetTime() > lastSaveResumeTime + 15 * 60 ) {
            lastSaveResumeTime = GetTime();
            saveTorrentResumeData();
            lockAndSaveUserData();
        }

        ses.reset();
        MilliSleep(5000);
    }
}

void ThreadSessionAlerts()
{
    static map<sha1_hash, bool> neighborCheck;
    static map<sha1_hash, int64_t> statusCheck;

    SimpleThreadCounter threadCounter(&cs_twister, &m_threadsToJoin, "session-alerts");

    while(!m_ses && !m_shuttingDownSession) {
        MilliSleep(200);
    }
    while (m_ses && !m_shuttingDownSession) {
        boost::shared_ptr<session> ses(m_ses);
        alert const* a = ses->wait_for_alert(seconds(1));
        if (a == 0) continue;

        std::deque<alert*> alerts;
        ses->pop_alerts(&alerts);
        std::string now = time_now_string();
        for (std::deque<alert*>::iterator i = alerts.begin()
                , end(alerts.end()); i != end; ++i)
        {
                // make sure to delete each alert
                std::unique_ptr<alert> a(*i);

                dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(*i);
                if (rd)
                {
                    if( rd->m_lst.size() ) {
                        // use first one to recover target
                        entry const *p = rd->m_lst.begin()->find_key("p");
                        if( p && p->type() == entry::dictionary_t ) {
                            entry const *target = p->find_key("target");
                            if( target && target->type() == entry::dictionary_t ) {
                                entry const *n = target->find_key("n");
                                entry const *r = target->find_key("r");
                                entry const *t = target->find_key("t");
                                if( n && n->type() == entry::string_t &&
                                    r && r->type() == entry::string_t &&
                                    t && t->type() == entry::string_t) {
                                    sha1_hash ih = dhtTargetHash(n->string(), r->string(), t->string());
                                    dhtgetMapPost(ih,*rd);
                                    DhtProxy::dhtgetPeerReqReply(ih,rd);
                                }
                            }
                        }
                    }
                    continue;
                }

                dht_get_data_alert const* gd = alert_cast<dht_get_data_alert>(*i);
                if (gd)
                {
                    if( gd->m_possiblyNeighbor ) {
                        entry const *n = gd->m_target.find_key("n");
                        entry const *r = gd->m_target.find_key("r");
                        entry const *t = gd->m_target.find_key("t");

                        if( n && n->type() == entry::string_t &&
                            r && r->type() == entry::string_t &&
                            t && t->type() == entry::string_t) {

                            // if this is a special resource then start another dhtget to make
                            // sure we are really its neighbor. don't do it needless.
                            if( m_specialResources.count(r->string()) ) {
                                // check if user exists
                                CTransaction txOut;
                                uint256 hashBlock;
                                if( !GetTransaction(n->string(), txOut, hashBlock) ) {
                                    printf("Special Resource but username is unknown - ignoring\n");
                                } else {
                                        // now we do our own search to make sure we are really close to this target
                                    sha1_hash ih = dhtTargetHash(n->string(), r->string(), t->string());

                                    bool knownTorrent = false;
                                    {
                                        LOCK(cs_twister);
                                        knownTorrent = m_userTorrent.count(n->string());
                                    }
                                    if( !knownTorrent ) {
                                        if( !neighborCheck.count(ih) ) {
#if DEBUG_NEIGHBOR_TORRENT
                                            printf("possiblyNeighbor of [%s,%s,%s] - starting a new dhtget to be sure\n",
                                                   n->string().c_str(),
                                                   r->string().c_str(),
                                                   t->string().c_str());
#endif
                                            neighborCheck[ih] = false;
                                            dhtGetData(n->string(), r->string(), t->string() == "m", false);
                                        } else if( neighborCheck[ih] ) {
                                            sha1_hash ihStatus = dhtTargetHash(n->string(), "status", "s");

                                            if( !statusCheck.count(ihStatus) ||
                                                statusCheck[ihStatus] + 3600 < GetTime() ) {
#if DEBUG_NEIGHBOR_TORRENT
                                                printf("known neighbor. starting a new dhtget check of [%s,%s,%s]\n",
                                                        n->string().c_str(), "status", "s");
#endif
                                                statusCheck[ihStatus] = GetTime();
                                                dhtGetData(n->string(), "status", false, false);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                    }
                    continue;
                }

                dht_reply_data_done_alert const* dd = alert_cast<dht_reply_data_done_alert>(*i);
                if (dd)
                {
#if DEBUG_NEIGHBOR_TORRENT
                    printf("get_data_done [%s,%s,%s] is_neighbor=%d got_data=%d\n",
                           dd->m_username.c_str(), dd->m_resource.c_str(), dd->m_multi ? "m" : "s",
                           dd->m_is_neighbor, dd->m_got_data);
#endif
                    sha1_hash ih = dhtTargetHash(dd->m_username, dd->m_resource, dd->m_multi ? "m" : "s");
                    if( !dd->m_got_data ) {
                        // no data: post alert to return from wait_for_alert in dhtget()
                        dhtgetMapPost(ih,*dd);
                        DhtProxy::dhtgetPeerReqReply(ih,dd);
                    }

                    if( neighborCheck.count(ih) ) {
                        neighborCheck[ih] = dd->m_is_neighbor;
                        if( dd->m_is_neighbor && dd->m_resource == "tracker" ) {
#if DEBUG_NEIGHBOR_TORRENT
                            printf("is neighbor. starting a new dhtget check of [%s,%s,%s]\n",
                                   dd->m_username.c_str(), "status", "s");
#endif
                            sha1_hash ihStatus = dhtTargetHash(dd->m_username, "status", "s");
                            statusCheck[ihStatus] = GetTime();
                            dhtGetData(dd->m_username, "status", false, false);
                        }
                    }
                    if( statusCheck.count(ih) ) {
                        if( dd->m_got_data ) {
                            startTorrentUser(dd->m_username, false);
                        }
                    }
                    continue;
                }

                save_resume_data_alert const* rda = alert_cast<save_resume_data_alert>(*i);
                if (rda) {
                    if (rda->resume_data) {
                        torrent_handle h = rda->handle;
                        torrent_status st = h.status(torrent_handle::query_save_path);
                        std::vector<char> out;
                        bencode(std::back_inserter(out), *rda->resume_data);
                        save_file(combine_path(st.save_path, to_hex(st.info_hash.to_string()) + ".resume"), out);
                    }
                }

                save_resume_data_failed_alert const *rdfa = alert_cast<save_resume_data_failed_alert>(*i);
                if (rda || rdfa)
                {
                    torrent_handle h = (rda) ? rda->handle : rdfa->handle;
                    torrent_status st = h.status();
                    LOCK(cs_twister);
                    num_outstanding_resume_data--;
                    if(m_peekTorrent.count(st.name) && st.paused) {
                        m_peekTorrent.erase(st.name);
                        ses->remove_torrent(h);
                    }
                }

                external_ip_alert const* ei = alert_cast<external_ip_alert>(*i);
                if (ei)
                {
                    boost::system::error_code ec;
                    std::string extip = ei->external_address.to_string(ec);

                    printf("Learned new external IP from DHT peers: %s\n", extip.c_str());
                    CNetAddr addrLocalHost(extip);

                    // pretend it came from querying http server. try voting up to 10 times
                    // to change current external ip in bitcoin code.
                    for(int i=0; i < 10; i++) {
                        AddLocal(addrLocalHost, LOCAL_HTTP);
                        const CNetAddr paddrPeer("8.8.8.8");
                        CAddress addr( GetLocalAddress(&paddrPeer) );
                        if( addr.IsValid() && addr.ToStringIP() == extip)
                            break;
                    }
                    continue;
                }
        }
    }
}

void ThreadHashtagsAging()
{
    SimpleThreadCounter threadCounter(&cs_twister, &m_threadsToJoin, "hashtags-aging");

    while(!m_ses && !m_shuttingDownSession) {
        MilliSleep(200);
    }

    while (m_ses && !m_shuttingDownSession) {

        {
            LOCK(cs_seenHashtags);
            for( std::map<std::string,double>::iterator iter = m_seenHashtags.begin(); iter != m_seenHashtags.end(); ) {
                iter->second *= hashtagAgingFactor;
                if( iter->second < hashtagCriticalValue ) {
                    m_seenHashtags.erase(iter++);
                } else {
                    ++iter;
                }
            }
        }

        for(int i=0; i<hashtagTimerInterval && !m_shuttingDownSession; ++i) {
            MilliSleep(1000);
        }
    }
}

void preinitSessionTorrent()
{
    boost::filesystem::path globalDataPath = GetDataDir() / GLOBAL_DATA_FILE;
    loadGlobalData(globalDataPath.string());
}

void startSessionTorrent(boost::thread_group& threadGroup)
{
    printf("startSessionTorrent (waiting for external IP)\n");

    m_specialResources["tracker"] = true;
    //m_specialResources["swarm"] = true;

    // these are the resources which shouldn't expire
    m_noExpireResources["avatar"] = SimpleNoExpire;
    m_noExpireResources["profile"] = SimpleNoExpire;
    m_noExpireResources["following"] = NumberedNoExpire;
    m_noExpireResources["status"] = SimpleNoExpire;
    m_noExpireResources["post"] = PostNoExpireRecent;

    DhtProxy::fEnabled = GetBoolArg("-dhtproxy", false);

    m_threadsToJoin = 0;
    threadGroup.create_thread(boost::bind(&ThreadWaitExtIP));
    threadGroup.create_thread(boost::bind(&ThreadMaintainDHTNodes));
    threadGroup.create_thread(boost::bind(&ThreadSessionAlerts));
    threadGroup.create_thread(boost::bind(&ThreadHashtagsAging));
}

void stopSessionTorrent()
{
    if( m_ses ){
            m_ses->pause();

            saveTorrentResumeData();

            printf("\nwaiting for resume data [%d]\n", num_outstanding_resume_data);
            while (num_outstanding_resume_data > 0)
            {
                MilliSleep(100);
            }

            m_shuttingDownSession = true;
            int threadsToJoin = 0;
            do {
                MilliSleep(100);
                LOCK(cs_twister);
                if( threadsToJoin != m_threadsToJoin ) {
                    threadsToJoin = m_threadsToJoin;
                    printf("twister threads to join = %d\n", threadsToJoin);
                }
            } while( threadsToJoin );

            printf("\nsaving session state\n");

            entry session_state;
            m_ses->save_state(session_state,
                            session::save_settings |
                            session::save_dht_settings |
                            session::save_dht_state |
                            session::save_encryption_settings |
                            session::save_as_map |
                            session::save_feeds);

            std::vector<char> out;
            bencode(std::back_inserter(out), session_state);
            boost::filesystem::path sesStatePath = GetDataDir() / "ses_state";
            save_file(sesStatePath.string(), out);

            m_ses->stop_dht();

            m_ses.reset();
    }

    boost::filesystem::path globalDataPath = GetDataDir() / GLOBAL_DATA_FILE;
    saveGlobalData(globalDataPath.string());

    lockAndSaveUserData();

    printf("libtorrent + dht stopped\n");
}

std::string createSignature(std::string const &strMessage, CKeyID &keyID)
{
    if (pwalletMain->IsLocked()) {
        printf("createSignature: Error please enter the wallet passphrase with walletpassphrase first.\n");
        return std::string();
    }

    CKey key;
    if (!pwalletMain->GetKey(keyID, key)) {
        printf("createSignature: private key not available for given keyid.\n");
        return std::string();
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        printf("createSignature: sign failed.\n");
        return std::string();
    }

    return std::string((const char *)&vchSig[0], vchSig.size());
}

std::string createSignature(std::string const &strMessage, std::string const &strUsername)
{
    if (pwalletMain->IsLocked()) {
        printf("createSignature: Error please enter the wallet passphrase with walletpassphrase first.\n");
        return std::string();
    }

    CKeyID keyID;
    if( !pwalletMain->GetKeyIdFromUsername(strUsername, keyID) ) {
        printf("createSignature: user '%s' unknown.\n", strUsername.c_str());
        return std::string();
    }

    return createSignature( strMessage, keyID );
}


bool getUserPubKey(std::string const &strUsername, CPubKey &pubkey, int maxHeight)
{
    CTransaction txOut;
    uint256 hashBlock;
    if( !GetTransaction(strUsername, txOut, hashBlock, maxHeight) ) {
        //printf("getUserPubKey: user unknown '%s'\n", strUsername.c_str());
        return false;
    }

    std::vector< std::vector<unsigned char> > vData;
    if( !txOut.pubKey.ExtractPushData(vData) || vData.size() < 1 ) {
        printf("getUserPubKey: broken pubkey for user '%s'\n", strUsername.c_str());
        return false;
    }
    pubkey = CPubKey(vData[0]);
    if( !pubkey.IsValid() ) {
        printf("getUserPubKey: invalid pubkey for user '%s'\n", strUsername.c_str());
        return false;
    }
    return true;
}


bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign, int maxHeight)
{
    CPubKey pubkey;
    if( !getUserPubKey(strUsername, pubkey, maxHeight) ) {
      printf("verifySignature: no pubkey for user '%s'\n", strUsername.c_str());
      return false;
    }

    vector<unsigned char> vchSig((const unsigned char*)strSign.data(),
                                 (const unsigned char*)strSign.data() + strSign.size());

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkeyRec;
    if (!pubkeyRec.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkeyRec.GetID() == pubkey.GetID());
}

void storeNewDM(const string &localuser, const string &dmUser, const StoredDirectMsg &stoDM)
{
    LOCK(cs_twister);
    // store this dm in memory list, but prevent duplicates
    std::vector<StoredDirectMsg> &dmsFromToUser = m_users[localuser].
                                  m_directmsg[dmUser];
    std::vector<StoredDirectMsg>::iterator it;
    for( it = dmsFromToUser.begin(); it != dmsFromToUser.end(); ++it ) {
        if( stoDM.m_utcTime == (*it).m_utcTime &&
            stoDM.m_text    == (*it).m_text ) {
            break;
        }
        if( stoDM.m_utcTime <= (*it).m_utcTime ) {
            dmsFromToUser.insert(it, stoDM);
            break;
        }
    }
    if( it == dmsFromToUser.end() ) {
        dmsFromToUser.push_back(stoDM);
    }
}

void storeGroupDM(const string &groupAlias, const StoredDirectMsg &stoDM)
{
    LOCK(cs_twister);
    if( !m_groups.count(groupAlias) )
        return;
    GroupChat &group = m_groups[groupAlias];

    BOOST_FOREACH(string const &member, group.m_members) {
        if( m_users.count(member) && !m_users.at(member).m_ignoreGroups.count(groupAlias) ) {
            storeNewDM(member,groupAlias,stoDM);
        }
    }
}

string getGroupAliasByKey(const string &privKey)
{
    string groupAlias;
    LOCK(cs_twister);
    map<string,GroupChat>::iterator i;
    for (i = m_groups.begin(); i != m_groups.end(); ++i) {
        if( i->second.m_privKey == privKey ) {
            groupAlias = i->first;
            break;
        }
    }
    return groupAlias;
}

void registerNewGroup(const string &privKey, const string &desc, const string &member, const string &invitedBy, int64_t utcTime, int k)
{
    string groupAlias = getGroupAliasByKey(privKey);

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(privKey);
    if (!fGood) {
        printf("registerGroupMember: Invalid private key\n");
        return;
    }
    CKey key = vchSecret.GetKey();
    CPubKey pubkey = key.GetPubKey();
    CKeyID vchAddress = pubkey.GetID();
    {
        LOCK(pwalletMain->cs_wallet);
        if (pwalletMain->HaveKey(vchAddress)) {
            // already exists? reuse same alias (trying to fix inconsistency wallet x groups)
            groupAlias = pwalletMain->mapKeyMetadata[vchAddress].username;
            if( !groupAlias.length() || groupAlias.at(0) != '*' ) {
                printf("registerGroupMember: Invalid group alias '%s' from wallet\n", groupAlias.c_str());
                return;
            }
        } else if (!groupAlias.length()) {
            groupAlias = getRandomGroupAlias();
        }

        pwalletMain->mapKeyMetadata[vchAddress] = CKeyMetadata(GetTime(), groupAlias);
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
            printf("registerGroupMember: Error adding key to wallet\n");
            return;
        }
    }

    LOCK(cs_twister);
    GroupChat &group = m_groups[groupAlias];
    group.m_description = desc;
    group.m_privKey     = privKey;

    if( member.length() ) {
        if( member == groupAlias ) {
            StoredDirectMsg stoDM;
            stoDM.m_fromMe  = false;
            stoDM.m_from    = invitedBy;
            stoDM.m_k       = k;
            // temporary hack: we must add new fields to StoredDirectMsg so text may be translated by UI
            stoDM.m_text    = "*** '" + invitedBy + "' changed group description to: " + desc;
            stoDM.m_utcTime = utcTime;
            storeGroupDM(groupAlias,stoDM);
        } else {
            group.m_members.insert(member);

            if( m_users.count(member) && !m_users.at(member).m_ignoreGroups.count(groupAlias) ) {
                StoredDirectMsg stoDM;
                stoDM.m_fromMe  = false;
                stoDM.m_from    = invitedBy;
                stoDM.m_k       = k;
                // temporary hack: we must add new fields to StoredDirectMsg so text may be translated by UI
                stoDM.m_text    = "*** Invited by '" + invitedBy + "' to group: " + desc;
                stoDM.m_utcTime = utcTime;
                storeNewDM(member,groupAlias,stoDM);
            }
        }
    }
}

void notifyNewGroupMember(string &groupAlias, string &newmember, string &invitedBy, int64_t utcTime, int k)
{
    LOCK(cs_twister);
    if( !m_groups.count(groupAlias) )
        return;

    GroupChat &group = m_groups[groupAlias];

    if( group.m_members.count(newmember) )
        return;

    group.m_members.insert(newmember);

    StoredDirectMsg stoDM;
    stoDM.m_fromMe  = false;
    stoDM.m_from    = invitedBy;
    stoDM.m_k       = k;
    // temporary hack: we must add new fields to StoredDirectMsg so text may be translated by UI
    stoDM.m_text    = "*** New member '" + newmember + "' invited by '" + invitedBy + "'";
    stoDM.m_utcTime = utcTime;
    storeGroupDM(groupAlias,stoDM);
}

// dispatch new msg for mentions and hashtags
void dispatchHM(string const &strMsg, string const &strUsername, entry const &v)
{
    if (strMsg.size() == 0)
        return;
    // split and look for mentions and hashtags
    vector<string> tokens;
    boost::algorithm::split(tokens,strMsg,boost::algorithm::is_any_of(msgTokensDelimiter),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 ) {
            char delim = token.at(0);
            if( delim != '#' && delim != '@' ) continue;
            string target = (delim == '#') ? "hashtag" : "mention";
            string word = token.substr(1);
#ifdef HAVE_BOOST_LOCALE
            word = boost::locale::to_lower(word);
#else
            boost::algorithm::to_lower(word);
#endif
            if( word.find(delim) == string::npos ) {
                dhtPutData(word, target, true,
                                 v, strUsername, GetAdjustedTime(), 0);
            } else {
                vector<string> subtokens;
                boost::algorithm::split(subtokens,word,std::bind1st(std::equal_to<char>(),delim),
                                        boost::algorithm::token_compress_on);
                BOOST_FOREACH(string const& word, subtokens) {
                    if( word.length() ) {
                        dhtPutData(word, target, true,
                                         v, strUsername, GetAdjustedTime(), 0);
                    }
                }
            }
        }
    }
}

// try decrypting new DM received by any torrent we follow
bool processReceivedDM(lazy_entry const* post)
{
    bool result = false;

    std::set<std::string> torrentsToStart;

    lazy_entry const* dm = post->dict_find_dict("dm");
    if( dm ) {
        ecies_secure_t sec;
        sec.key = dm->dict_find_string_value("key");
        sec.mac = dm->dict_find_string_value("mac");
        sec.orig = dm->dict_find_int_value("orig");
        sec.body = dm->dict_find_string_value("body");

        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CKeyID, CKeyMetadata)& item, pwalletMain->mapKeyMetadata)
        {
            CKey key;
            if (!pwalletMain->GetKey(item.first, key)) {
                printf("processReceivedDM: private key not available trying to decrypt DM.\n");
            } else {
                std::string textOut;
                if( key.Decrypt(sec, textOut) ) {
                    result = true;
                    /* this printf is good for debug, but bad for security.
                    printf("Received DM for user '%s' text = '%s'\n",
                           item.second.username.c_str(),
                           textOut.c_str());
                    */

                    int64_t     utcTime = post->dict_find_int_value("time");
                    std::string from    = post->dict_find_string_value("n");
                    int         k       = post->dict_find_int_value("k",-1);
                    std::string to      = item.second.username; // default (old format)
                    std::string msg     = textOut;              // default (old format)
                    bool        fromMe  = (from == to);
                    bool        isGroup = false;

                    {
                        LOCK(cs_twister);
                        isGroup = m_groups.count(to);
                        if( !isGroup && m_users.count(to) &&
                            !m_users.at(to).m_following.count(from) ) {
                            /* DM not allowed from users we don't follow.*/
                            printf("processReceivedDM: from '%s' to '%s' not allowed (not following)\n",
                                   from.c_str(), to.c_str());
                            break;
                        }
                    }

                    // try bdecoding the new format (copy to self etc)
                    {
                        lazy_entry v;
                        int pos;
                        libtorrent::error_code ec;
                        if (lazy_bdecode(textOut.data(), textOut.data()+textOut.size(), v, ec, &pos) == 0
                                && v.type() == lazy_entry::dict_t) {

                            /* group_invite: register new private key and group's description.
                             * if sent to groupalias then it is a change description request. */
                            lazy_entry const* pGroupInvite = v.dict_find_dict("group_invite");
                            if (pGroupInvite) {
                                lazy_entry const* pDesc = pGroupInvite->dict_find_string("desc");
                                lazy_entry const* pKey  = pGroupInvite->dict_find_string("key");
                                if (pDesc && pKey) {
                                    string desc     = pDesc->string_value();
                                    string privKey  = pKey->string_value();
                                    registerNewGroup(privKey, desc, to, from, utcTime, k);
                                }
                                break;
                            }

                            /* update group members list. we may need to start torrent for
                             * new members to receive their chat updates */
                            lazy_entry const* pGroupMembers = v.dict_find_list("group_members");
                            if (pGroupMembers && isGroup) {
                                for (int i = 0; i < pGroupMembers->list_size(); ++i) {
                                    std::string member = pGroupMembers->list_string_value_at(i);
                                    if (member.empty()) continue;
                                    notifyNewGroupMember(to, member, from, utcTime, k);
                                    torrentsToStart.insert(member);
                                }
                                break;
                            }

                            lazy_entry const* pMsg = v.dict_find_string("msg");
                            lazy_entry const* pTo  = v.dict_find_string("to");
                            if (pMsg && pTo) {
                                msg = pMsg->string_value();
                                to  = pTo->string_value();
                                // new features here: key distribution etc
                            }
                        }
                    }

                    if( !msg.length() || !to.length() )
                        break;

                    StoredDirectMsg stoDM;
                    stoDM.m_fromMe  = fromMe;
                    stoDM.m_from    = from;
                    stoDM.m_k       = k;
                    stoDM.m_text    = msg;
                    stoDM.m_utcTime = utcTime;

                    if( isGroup ) {
                        storeGroupDM(item.second.username, stoDM);
                    } else {
                        storeNewDM(item.second.username, fromMe ? to : from, stoDM);
                    }
#ifdef ENABLE_WS
                    if (GetBoolArg("-websocket", false) && !fromMe)
                    {
                        Object dm;

                        dm.push_back(Pair("type", isGroup ? "GROUP" : "DM"));
                        if (isGroup)
                            dm.push_back(Pair("group", item.second.username));
                        dm.push_back(Pair("k", k));
                        dm.push_back(Pair("time", utcTime));
                        dm.push_back(Pair("from", from));
                        dm.push_back(Pair("to", to));
                        dm.push_back(Pair("msg", msg));

                        WriteToWS(dm);
                    }
#endif // ENABLE_WS
                    break;
                }
            }
        }
    }

    // start torrents outside cs_wallet to prevent deadlocks
    BOOST_FOREACH(string username, torrentsToStart) {
        startTorrentUser(username, true);
    }

    return result;
}

// check post received in a torrent we follow if they mention local users
void processReceivedPost(lazy_entry const &v, std::string &username, int64 time, std::string &msg)
{
    // split and look for mentions for local users
    vector<string> tokens;
    boost::algorithm::split(tokens,msg,boost::algorithm::is_any_of(msgTokensDelimiter),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 ) {
            char delim = token.at(0);
            if( delim != '@' ) continue;
            string mentionUser = token.substr(1);
#ifdef HAVE_BOOST_LOCALE
            mentionUser = boost::locale::to_lower(mentionUser);
#else
            boost::algorithm::to_lower(mentionUser);
#endif

            LOCK(cs_twister);
            // mention of a local user && sent by someone we follow
            if( m_users.count(mentionUser) && m_users[mentionUser].m_following.count(username) )
            {
                std::string postKey = username + ";" + boost::lexical_cast<std::string>(time);
                if( m_users[mentionUser].m_mentionsKeys.count(postKey) == 0 )
                {
                    m_users[mentionUser].m_mentionsKeys.insert(postKey);
                    entry vEntry;
                    vEntry = v;
                    m_users[mentionUser].m_mentionsPosts.push_back(vEntry);
#ifdef ENABLE_WS
                    if (GetBoolArg("-websocket", false))
                    {
                        Object obj;

                        obj.push_back(Pair("type", "mention"));
                        obj.push_back(Pair("from", username));
                        obj.push_back(Pair("to", mentionUser));
                        hexcapePost(vEntry);
                        obj.push_back(Pair("post", entryToJson(vEntry)));

                        WriteToWS(obj);
                    }
#endif // ENABLE_WS
                }
            }
        }
    }
#ifdef ENABLE_WS
    if (GetBoolArg("-websocket", false))
    {
        entry vEntry;
        vEntry = v;
        for (map<string, UserData>::const_iterator it = m_users.begin();
             it != m_users.end();
             ++it)
        {
            if (it->second.m_following.count(username))
            {
                Object obj;

                obj.push_back(Pair("type", "post"));
                obj.push_back(Pair("postboard", it->first));
                obj.push_back(Pair("from", username));
                hexcapePost(vEntry);
                obj.push_back(Pair("post", entryToJson(vEntry)));

                WriteToWS(obj);
            }
        }
    }
#endif // ENABLE_WS
}

bool acceptSignedPost(char const *data, int data_size, std::string username, int seq, std::string &errmsg, boost::uint32_t *flags)
{
    bool ret = false;
    char errbuf[200]="";
    if( flags ) *flags = 0;

    lazy_entry v;
    int pos;
    libtorrent::error_code ec;
    if (data_size <= 0 || data_size > 2048 ) {
        sprintf(errbuf,"bad bencoded post size");
    } else if (lazy_bdecode(data, data + data_size, v, ec, &pos) == 0) {

        if( v.type() == lazy_entry::dict_t ) {
            lazy_entry const* post = v.dict_find_dict("userpost");
            std::string sig = v.dict_find_string_value("sig_userpost");

            if( !post || !sig.size() ) {
                sprintf(errbuf,"missing post or signature.");
            } else {
                std::string n = post->dict_find_string_value("n");
                std::string msg = post->dict_find_string_value("msg");
                int msgUtf8Chars = utf8::num_characters(msg.begin(), msg.end());
                int k = post->dict_find_int_value("k",-1);
                int height = post->dict_find_int_value("height",-1);
                int64 time = post->dict_find_int_value("time",-1);

                if( n != username ) {
                    sprintf(errbuf,"expected username '%s' got '%s'",
                            username.c_str(),n.c_str());
                } else if( k != seq ) {
                    sprintf(errbuf,"expected piece '%d' got '%d'",
                           seq, k);
                } else if( !validatePostNumberForUser(username, k) ) {
                    sprintf(errbuf,"too much posts from user '%s' rejecting post",
                            username.c_str());
                } else if( height < 0 || (height > getBestHeight()+1 && getBestHeight() > 0) ) {
                    sprintf(errbuf,"post from future not accepted (height: %d > %d)",
                            height, getBestHeight());
                } else if( msgUtf8Chars < 0 ) {
                    sprintf(errbuf,"invalid utf8 string");
                } else if( msgUtf8Chars > 140 ) {
                    sprintf(errbuf,"msg too big (%d > 140)", msgUtf8Chars);
                } else {
                    std::pair<char const*, int> postbuf = post->data_section();
                    ret = verifySignature(
                            std::string(postbuf.first,postbuf.second),
                            username, sig, height);
                    if( !ret ) {
                        sprintf(errbuf,"bad post signature");
                    } else {
                        lazy_entry const* rt = post->dict_find_dict("rt");
                        std::string sig_rt = post->dict_find_string_value("sig_rt");

                        if( rt ) {
                            if( flags ) (*flags) |= USERPOST_FLAG_RT;
                            std::string username_rt = rt->dict_find_string_value("n");
                            int height_rt = rt->dict_find_int_value("height",-1);

                            std::pair<char const*, int> rtbuf = rt->data_section();
                            ret = verifySignature(
                                    std::string(rtbuf.first,rtbuf.second),
                                    username_rt, sig_rt, height_rt);
                            if( !ret ) {
                                sprintf(errbuf,"bad RT signature");
                            }
                        }

                        lazy_entry const* fav = post->dict_find_dict("fav");
                        string sig_fav = post->dict_find_string_value("sig_fav");

                        if ( fav ) {
                            if ( flags )
                                (*flags) |= USERPOST_FLAG_FAV;
                            string username_fav = fav->dict_find_string_value("n");
                            int height_fav = fav->dict_find_int_value("height", -1);

                            pair<char const*, int> favbuf = fav->data_section();
                            ret = verifySignature(string(favbuf.first, favbuf.second),
                                                  username_fav, sig_fav, height_fav);
                            if ( !ret )
                                sprintf(errbuf, "bad FAV signature");
                        }

                        if( flags ) {
                            lazy_entry const* dm = post->dict_find_dict("dm");
                            lazy_entry const* pfav = post->dict_find_dict("pfav");
                            if( dm ) {
                                (*flags) |= USERPOST_FLAG_DM;
                                processReceivedDM(post);
                            } else if (pfav) {
                                (*flags) |= USERPOST_FLAG_P_FAV;
                            } else {
                                processReceivedPost(v, username, time, msg);
                            }
                        }
                    }
                }
            }
        }
    }

    errmsg = errbuf;
#ifdef DEBUG_ACCEPT_POST
    if( !ret ) {
        printf("acceptSignedPost: %s\n",errbuf);
    }
#endif
    return ret;
}

bool validatePostNumberForUser(std::string const &username, int k)
{
    CTransaction txOut;
    uint256 hashBlock;
    if( !GetTransaction(username, txOut, hashBlock) ) {
        printf("validatePostNumberForUser: username is unknown\n");
        return false;
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];

    if( k < 0 )
        return false;
    if( getBestHeight() > 0 && k > 2*(getBestHeight() - pblockindex->nHeight) + 20)
        return false;

    return true;
}

bool usernameExists(std::string const &username)
{
    CTransaction txOut;
    uint256 hashBlock;
    return GetTransaction(username, txOut, hashBlock);
}


/*
"userpost" :
{
        "n" : username,
        "k" : seq number,
        "t" : "post" / "dm" / "rt"
        "msg" : message (post/rt)
        "time" : unix utc
        "height" : best height at user
        "dm" : encrypted message (dm) -opt
        "rt" : original userpost - opt
        "sig_rt" : sig of rt - opt
        "reply" : - opt
        {
                "n" : reference username
                "k" : reference k
        }
}
"sig_userpost" : signature by userpost.n
*/

bool createSignedUserpost(entry &v, std::string const &username, int k,
                          int flag, std::string const &msg,
                          entry const *ent, entry const *sig_rtfav,
                          std::string const &reply_n = "", int reply_k = 0)
{
    entry &userpost = v["userpost"];

    //
    userpost["n"] = username;
    userpost["k"] = k;
    userpost["time"] = GetAdjustedTime();
    userpost["height"] = getBestHeight() - 1; // be conservative

    int msgUtf8Chars = utf8::num_characters(msg.begin(), msg.end());
    if(msgUtf8Chars < 0) {
        return false; // invalid utf8
    } else if (msgUtf8Chars && msgUtf8Chars <= 140) {
        userpost["msg"] = msg;
    } else {
        // break into msg and msg2 fields to overcome 140ch checks
        string::const_iterator it = msg.begin();
        string::const_iterator end = msg.end();
        string msgOut, msg2Out;
        int count = 0;
        while (it!= end) {
            string::const_iterator itPrev = it;
            utf8::internal::utf_error err_code = utf8::internal::validate_next(it, end);
            assert(err_code == utf8::internal::UTF8_OK); // string must have been validated already
            count++;
            if( count <= 140 ) {
                msgOut.append(itPrev,it);
            } else {
                msg2Out.append(itPrev,it);
            }
        }
        userpost["msg"] = msgOut;
        userpost["msg2"] = msg2Out;
    }

    switch(flag)
    {
    case USERPOST_FLAG_RT:
    {
        if (msg.size())
        {
            std::vector<char> buf;
            bencode(std::back_inserter(buf), userpost);
            std::string sig = createSignature(std::string(buf.data(),buf.size()), username);
            if(sig.size())
            {
                v["sig_wort"] = sig;
            } else {
                return false;
            }
        }
        //userpost["t"] = "rt";
        userpost["rt"] = *ent;
        userpost["sig_rt"] = *sig_rtfav;
        break;
    }
    case USERPOST_FLAG_FAV:
        userpost["fav"] = *ent;
        userpost["sig_fav"] = *sig_rtfav;
        break;
    case USERPOST_FLAG_DM:
        //userpost["t"] = "dm";
        userpost["dm"] = *ent;
        break;
    case USERPOST_FLAG_P_FAV:
        userpost["pfav"] = *ent;
        break;
    default:
        break;
    }

    if( reply_n.size() ) {
        entry &reply = userpost["reply"];
        reply["n"]=reply_n;
        reply["k"]=reply_k;
    }
    //

    std::vector<char> buf;
    bencode(std::back_inserter(buf), userpost);
    std::string sig = createSignature(std::string(buf.data(),buf.size()), username);
    if( sig.size() ) {
        v["sig_userpost"] = sig;
        return true;
    } else {
        return false;
    }
}

bool createDirectMessage(entry &dm, std::string const &to, std::string const &msg)
{
    CPubKey pubkey;

    /* try obtaining key from wallet first */
    CKeyID keyID;
    if (pwalletMain->GetKeyIdFromUsername(to, keyID) &&
        pwalletMain->GetPubKey( keyID, pubkey) ) {
        /* success: key obtained from wallet */
    } else if( !getUserPubKey(to, pubkey) ) {
      printf("createDirectMessage: no pubkey for user '%s'\n", to.c_str());
      return false;
    }

    ecies_secure_t sec;
    bool encrypted = pubkey.Encrypt(msg, sec);

    if( encrypted ) {
        dm["key"] = sec.key;
        dm["mac"] = sec.mac;
        dm["orig"] = sec.orig;
        dm["body"] = sec.body;
    }

    return encrypted;
}

int getBestHeight()
{
    return nBestHeight;
}

bool shouldDhtResourceExpire(std::string resource, bool multi, int height)
{
    if ((height + BLOCK_AGE_TO_EXPIRE_DHT_ENTRY) < getBestHeight() ) {
        if( multi ) {
#ifdef DEBUG_EXPIRE_DHT_ITEM
            printf("shouldDhtResourceExpire: expiring resource multi '%s'\n", resource.c_str());
#endif
            return true;
        }

        // extract basic resource string (without numbering)
        std::string resourceBasic;
        for(size_t i = 0; i < resource.size() && isalpha(resource.at(i)); i++) {
            resourceBasic.push_back(resource.at(i));
        }

        int resourceNumber = -1;
        if( resource.length() > resourceBasic.length() ) {
            // make sure it is a valid number following (all digits)
            if( resource.at(resourceBasic.length()) == '0' &&
                resource.size() > resourceBasic.length() + 1 ){
                // leading zeros not allowed
            } else {
                size_t i;
                for(i = resourceBasic.length(); i < resource.size() &&
                    isdigit(resource.at(i)); i++) {
                }
                if(i == resource.size()) {
                    resourceNumber = atoi( resource.c_str() + resourceBasic.length() );
                }
            }
        }

        if( !m_noExpireResources.count(resourceBasic) ) {
            // unknown resource. expire it.
#ifdef DEBUG_EXPIRE_DHT_ITEM
            printf("shouldDhtResourceExpire: expiring non-special resource '%s'\n", resource.c_str());
#endif
            return true;
        } else {
            if( m_noExpireResources[resourceBasic] == SimpleNoExpire &&
                resource.length() > resourceBasic.length() ) {
                // this resource admits no number. expire it!
#ifdef DEBUG_EXPIRE_DHT_ITEM
                printf("shouldDhtResourceExpire: expiring resource with unexpected numbering '%s'\n", resource.c_str());
#endif
                return true;
            }
            if( m_noExpireResources[resourceBasic] == NumberedNoExpire &&
                (resourceNumber < 0 || resourceNumber > 200) ) {
                // try keeping a sane number here, otherwise expire it!
#ifdef DEBUG_EXPIRE_DHT_ITEM
                printf("shouldDhtResourceExpire: expiring numbered resource with no sane number '%s'\n", resource.c_str());
#endif
                return true;
            }
            if( m_noExpireResources[resourceBasic] == PostNoExpireRecent && resourceNumber < 0 ) {
#ifdef DEBUG_EXPIRE_DHT_ITEM
                printf("shouldDhtResourceExpire: expiring post with invalid numbering '%s'\n", resource.c_str());
#endif
                return true;
            }
            if( m_noExpireResources[resourceBasic] == PostNoExpireRecent &&
                (height + BLOCK_AGE_TO_EXPIRE_DHT_POSTS) < getBestHeight() ) {
#ifdef DEBUG_EXPIRE_DHT_ITEM
                printf("shouldDhtResourceExpire: expiring old post resource '%s' (height %d cur %d)\n",
                       resource.c_str(), height, getBestHeight());
#endif
                return true;
            }
        }
    }
    return false;
}

void receivedSpamMessage(std::string const &message, std::string const &user)
{
    LOCK(cs_spamMsg);
    bool hasSingleLangCode = (message.find("[") == message.rfind("["));
    bool hasPreferredLang  = m_preferredSpamLang.length() > 2;
    bool isSameLang        = hasPreferredLang && hasSingleLangCode &&
                             message.find(m_preferredSpamLang) != string::npos;
    bool currentlyEmpty    = !m_receivedSpamMsgStr.length();

    if( currentlyEmpty || (isSameLang && rand() < (RAND_MAX/2)) ) {
        m_receivedSpamMsgStr = message;
        m_receivedSpamUserStr = user;
        m_receivedSpamHeight = nBestHeight;
    }
}

void updateSeenHashtags(std::string &message, int64_t msgTime)
{
    if( message.find('#') == string::npos )
        return;

    // split and look for hashtags
    vector<string> tokens;
    set<string> hashtags;
    boost::algorithm::split(tokens,message,boost::algorithm::is_any_of(msgTokensDelimiter),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 && token.at(0) == '#' ) {
            string word = token.substr(1);
#ifdef HAVE_BOOST_LOCALE
            word = boost::locale::to_lower(word);
#else
            boost::algorithm::to_lower(word);
#endif
            if( word.find('#') == string::npos ) {
                hashtags.insert(word);
            } else {
                vector<string> subtokens;
                boost::algorithm::split(subtokens,word,std::bind1st(std::equal_to<char>(),'#'),
                                        boost::algorithm::token_compress_on);
                BOOST_FOREACH(string const& word, subtokens) {
                    if( word.length() ) {
                        hashtags.insert(word);
                    }
                }
            }
        }
    }

    if( hashtags.size() ) {
        boost::int64_t curTime = GetAdjustedTime();
        if( msgTime > curTime ) msgTime = curTime;

        double timeDiff = (curTime - msgTime);
        double vote = pow(0.5, timeDiff/hashtagHalfLife);

        LOCK(cs_seenHashtags);
        BOOST_FOREACH(string const& word, hashtags) {
            if( m_seenHashtags.count(word) ) {
                m_seenHashtags[word] += vote;
            } else {
                m_seenHashtags[word] = vote;
            }
        }
    }
}

entry formatSpamPost(const string &msg, const string &username, uint64_t utcTime = 0, int height = 0)
{
    entry v;
    entry &userpost = v["userpost"];

    userpost["n"] = username;
    userpost["k"] = height ? height : 1;
    userpost["time"] = utcTime ? utcTime : GetAdjustedTime();
    userpost["height"] = height ? height : getBestHeight();
    userpost["msg"] = msg;

    v["sig_userpost"] = "";
    return v;
}


void dhtGetData(std::string const &username, std::string const &resource, bool multi, bool local)
{
    if( DhtProxy::fEnabled ) {
        printf("dhtGetData: not allowed - using proxy (bug!)\n");
        return;
    }
    boost::shared_ptr<session> ses(m_ses);
    if( !ses ) {
        printf("dhtGetData: libtorrent session not ready\n");
        return;
    }
    ses->dht_getData(username,resource,multi,local);
}

void dhtPutData(std::string const &username, std::string const &resource, bool multi,
                entry const &value, std::string const &sig_user,
                boost::int64_t timeutc, int seq)
{
    // construct p dictionary and sign it
    entry p;
    entry& target = p["target"];
    target["n"] = username;
    target["r"] = resource;
    target["t"] = (multi) ? "m" : "s";
    if (seq >= 0 && !multi) p["seq"] = seq;
    p["v"] = value;
    p["time"] = timeutc;
    int height = getBestHeight()-1; // be conservative
    p["height"] = height;

    std::vector<char> pbuf;
    bencode(std::back_inserter(pbuf), p);
    std::string str_p = std::string(pbuf.data(),pbuf.size());
    std::string sig_p = createSignature(str_p, sig_user);
    if( !sig_p.size() ) {
        printf("dhtPutData: createSignature error for user '%s'\n", sig_user.c_str());
        return;
    }

    if( !DhtProxy::fEnabled ) {
        dhtPutDataSigned(username,resource,multi,p,sig_p,sig_user, true);
    } else {
        DhtProxy::dhtputRequest(username,resource,multi,str_p,sig_p,sig_user);
    }
}

void dhtPutDataSigned(std::string const &username, std::string const &resource, bool multi,
                libtorrent::entry const &p, std::string const &sig_p, std::string const &sig_user, bool local)
{
    if( DhtProxy::fEnabled ) {
        printf("dhtputDataSigned: not allowed - using proxy (bug!)\n");
        return;
    }
    boost::shared_ptr<session> ses(m_ses);
    if( !ses ) {
        printf("dhtPutData: libtorrent session not ready\n");
        return;
    }

    ses->dht_putDataSigned(username,resource,multi,p,sig_p,sig_user, local);
}

Value dhtput(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 5 || params.size() > 6)
        throw runtime_error(
            "dhtput <username> <resource> <s(ingle)/m(ulti)> <value> <sig_user> <seq>\n"
            "Store resource in dht network");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    string strResource = params[1].get_str();
    string strMulti    = params[2].get_str();
    entry value = jsonToEntry(params[3]);
    // value is already "p":"v": contents, so post may be unhexcaped directly
    unHexcapePost(value);
    string strSigUser  = params[4].get_str();

    // Test for private key here to avoid going into dht
    CKeyID keyID;
    if( !pwalletMain->GetKeyIdFromUsername(strSigUser, keyID) )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: no sig_user in wallet");
    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key of sig_user not available");

    bool multi = (strMulti == "m");
    if( !multi && params.size() != 6 )
        throw JSONRPCError(RPC_WALLET_ERROR, "Seq parameter required for single");

    int seq = -1;
    if( params.size() == 6 )
        seq = params[5].get_int();

    if( !multi && strUsername != strSigUser )
        throw JSONRPCError(RPC_WALLET_ERROR, "Username must be the same as sig_user for single");

    boost::int64_t timeutc = GetAdjustedTime();

    dhtPutData(strUsername, strResource, multi, value, strSigUser, timeutc, seq);

    return Value();
}

Value dhtputraw(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dhtputraw <hexdata>\n"
            "Store resource in dht network");

    string hexdata = params[0].get_str();

    vector<unsigned char> vch = ParseHex(hexdata);

    lazy_entry dhtroot;
    int pos;
    libtorrent::error_code ec;
    if (lazy_bdecode((const char *)vch.data(), (const char *)vch.data()+vch.size(), dhtroot, ec, &pos) != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"hexdata failed to bdecode");
    }
    if( dhtroot.type() != lazy_entry::dict_t) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"root not dict type");
    }
    lazy_entry const* p = dhtroot.dict_find_dict("p");
    if( !p ) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"missing 'p' entry");
    }
    lazy_entry const* target = p->dict_find_dict("target");
    if( !target ) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"missing 'target' entry");
    }

    string username = target->dict_find_string_value("n");
    string resource = target->dict_find_string_value("r");
    bool multi = target->dict_find_string_value("t") == "m";

    string sig_p = dhtroot.dict_find_string_value("sig_p");
    if( !sig_p.length() ) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"missing 'sig_p' entry");
    }

    string sig_user = dhtroot.dict_find_string_value("sig_user");
    if( !sig_user.length() ) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"missing 'sig_user' entry");
    }

    std::pair<char const*, int> pbuf = p->data_section();
    if (!verifySignature(std::string(pbuf.first,pbuf.second),
                sig_user,sig_p)) {
        throw JSONRPCError(RPC_INVALID_PARAMS,"invalid signature");
    }

    entry pEntry;
    pEntry = *p;
    dhtPutDataSigned(username, resource, multi,
                     pEntry, sig_p, sig_user, true);
    return Value();
}

Value dhtget(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "dhtget <username> <resource> <s(ingle)/m(ulti)> [timeout_ms] [timeout_multi_ms] [min_multi]\n"
            "Get resource from dht network");

    boost::shared_ptr<session> ses(m_ses);
    if( !ses )
        return Array();

    string strUsername = params[0].get_str();
    string strResource = params[1].get_str();
    string strMulti    = params[2].get_str();
    bool multi = (strMulti == "m");

    time_duration timeToWait = seconds(10);
    time_duration timeToWaitMulti = milliseconds(100);
    int minMultiReplies = 3;
    int lastSeq = -1;

    if( params.size() > 3 )
        timeToWait = milliseconds(params[3].get_int());
    if( params.size() > 4 )
        timeToWaitMulti = milliseconds(params[4].get_int());
    if( params.size() > 5 )
        minMultiReplies = params[5].get_int();

    alert_manager am(10, alert::dht_notification);
    sha1_hash ih = dhtTargetHash(strUsername,strResource,strMulti);

    vector<CNode*> dhtProxyNodes;
    if( !DhtProxy::fEnabled ) {
        dhtgetMapAdd(ih, &am);
        dhtGetData(strUsername, strResource, multi, true);
    } else {
        DhtProxy::dhtgetMapAdd(ih, &am);
        dhtProxyNodes = DhtProxy::dhtgetStartRequest(strUsername, strResource, multi);
    }

    Array ret;
    std::set<std::string> uniqueSigPs;

    int repliesReceived = 0;
    while( am.wait_for_alert(timeToWait) ) {
        std::unique_ptr<alert> a(am.get());

        dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(&(*a));
        if( rd ) {
            entry::list_type dhtLst = rd->m_lst;
            entry::list_type::iterator it;
            for( it = dhtLst.begin(); it != dhtLst.end(); ++it ) {
                libtorrent::entry &e = *it;
                hexcapeDht( e );
                string sig_p = safeGetEntryString(e, "sig_p");
                int seq = (multi) ? 0 : safeGetEntryInt( safeGetEntryDict(e,"p"), "seq" );
                bool acceptEntry = (multi) ? (!sig_p.length() || !uniqueSigPs.count(sig_p)) :
                                             (seq > lastSeq);
                if( acceptEntry ) {
                    if( !multi) {
                        ret.clear();
                    }
                    ret.push_back( entryToJson(e) );
                    lastSeq = seq;
                    if( sig_p.length() ) {
                        uniqueSigPs.insert(sig_p);
                    }
                }
            }
            //printf("dhtget: got %zd entries %zd unique\n", dhtLst.size(), uniqueSigPs.size());
        } else {
            // cast failed => dht_reply_data_done_alert => no data
            break;
        }

        if( repliesReceived++ < minMultiReplies ) {
            timeToWait = timeToWaitMulti;
            //printf("dhtget: wait again repliesReceived=%d lastSeq=%d\n", repliesReceived, lastSeq);
        } else {
            break;
        }
    }

    if( !DhtProxy::fEnabled ) {
        dhtgetMapRemove(ih,&am);
    } else {
        DhtProxy::dhtgetMapRemove(ih,&am);
        DhtProxy::dhtgetStopRequest(dhtProxyNodes, strUsername, strResource, multi);
    }

    return ret;
}

int findLastPublicPostLocalUser( std::string strUsername )
{
    int lastk = -1;

    torrent_handle h = getTorrentUser(strUsername);
    if( h.is_valid() ){
        std::vector<std::string> pieces;
        int max_id = std::numeric_limits<int>::max();
        int since_id = -1;
        h.get_pieces(pieces, 1, max_id, since_id, USERPOST_FLAG_HOME, 0);

        if( pieces.size() ) {
            string const& piece = pieces.front();
            lazy_entry v;
            int pos;
            libtorrent::error_code ec;
            if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0 &&
                v.type() == lazy_entry::dict_t) {
                lazy_entry const* post = v.dict_find_dict("userpost");
                lastk = post->dict_find_int_value("k",-1);
            }
        }
    }
    return lastk;
}


Value newpostmsg(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 3 && params.size() != 5))
        throw runtime_error(
            "newpostmsg <username> <k> <msg> [reply_n] [reply_k]\n"
            "Post a new message to swarm");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strK        = boost::lexical_cast<std::string>(k);
    string strMsg      = params[2].get_str();

    string strReplyN, strReplyK;
    int replyK = 0;
    if( params.size() == 5 ) {
        strReplyN  = params[3].get_str();
        replyK = params[4].get_int();
        strReplyK = boost::lexical_cast<std::string>(replyK);
    }

    entry v;
    // [MF] Warning: findLastPublicPostLocalUser requires that we follow ourselves
    int lastk = findLastPublicPostLocalUser(strUsername);
    if( lastk >= 0 )
        v["userpost"]["lastk"] = lastk;

    if( !createSignedUserpost(v, strUsername, k, 0,
                              strMsg, NULL, NULL,
                              strReplyN, replyK) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername, true);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        dhtPutData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), 1);
    }

    // post to dht as well
    dhtPutData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), 1);
    dhtPutData(strUsername, string("status"), false,
                     v, strUsername, GetAdjustedTime(), k);

    // is this a reply? notify
    if( strReplyN.length() ) {
        dhtPutData(strReplyN, string("replies")+strReplyK, true,
                         v, strUsername, GetAdjustedTime(), 0);
    }

    //look for mentions and hashtags in msg
    dispatchHM(strMsg, strUsername, v);

    hexcapePost(v);
    return entryToJson(v);
}

Value newpostcustom(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "newpostcustom <username> <k> '{\"field1\":value,\"field2\":value,...}'\n"
            "Create a post with custom fields and add it to swarm");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strK        = boost::lexical_cast<std::string>(k);
    Object fields      = params[2].get_obj();

    entry v;
    entry &userpost = v["userpost"];
    // [MF] Warning: findLastPublicPostLocalUser requires that we follow ourselves
    int lastk = findLastPublicPostLocalUser(strUsername);
    if( lastk >= 0 )
        userpost["lastk"] = lastk;

    for (Object::const_iterator i = fields.begin(); i != fields.end(); ++i) {
        if( i->value_.type() == str_type ) {
            userpost[i->name_] = i->value_.get_str();
        } else if ( i->value_.type() == int_type ) {
            userpost[i->name_] = i->value_.get_int();
        } else {
            JSONRPCError(RPC_INVALID_PARAMS,string("unknown type for parameter: ") + i->name_);
        }
    }

    if( !createSignedUserpost(v, strUsername, k, 0,
                              "", NULL, NULL) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername, true);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        dhtPutData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), 1);
    }

    // post to dht as well
    dhtPutData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), 1);
    if( userpost.find_key("msg") ) {
        dhtPutData(strUsername, string("status"), false,
                         v, strUsername, GetAdjustedTime(), k);
        //look for mentions and hashtags in msg
        dispatchHM(userpost["msg"].string(), strUsername, v);
    }

    hexcapePost(v);
    return entryToJson(v);
}

Value newpostraw(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "newpostraw <username> <k> <hexdata>\n"
            "Post a new raw post (already signed) to swarm");

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string hexdata     = params[2].get_str();

    vector<unsigned char> buf = ParseHex(hexdata);

    std::string errmsg;
    if( !acceptSignedPost((const char *)buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = getTorrentUser(strUsername);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,(const char *)buf.data(),buf.size());
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR,"swarm resource forwarding not implemented");
    }
    return Value();
}

Value newdirectmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5 )
        throw runtime_error(
            "newdirectmsg <from> <k> <to> <msg> [copy_self=false]\n"
            "Post a new dm to swarm.\n"
            "if copy_self true will increase k twice (two DMs).");

    EnsureWalletIsUnlocked();

    string strFrom     = params[0].get_str();
    int k              = params[1].get_int();
    string strTo       = params[2].get_str();
    string strMsg      = params[3].get_str();
    bool copySelf      = (params.size() > 4) ? params[4].get_bool() : false;

    std::list<entry *> dmsToSend;

    entry payloadNewFormat;
    payloadNewFormat["msg"] = strMsg;
    payloadNewFormat["to"]  = strTo;
    std::vector<char> payloadbuf;
    bencode(std::back_inserter(payloadbuf), payloadNewFormat);
    std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

    entry dmRcpt;
    if( !createDirectMessage(dmRcpt, strTo, strMsgData) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "error encrypting to pubkey of destination user");

    entry dmSelf;
    if( copySelf ) {
        // use new format to send a copy to ourselves. in future, message
        // to others might use the new format as well.
        if( !createDirectMessage(dmSelf, strFrom, strMsgData) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "error encrypting to pubkey to ourselve");

        if( rand() < (RAND_MAX/2) ) {
            dmsToSend.push_back(&dmRcpt);
            dmsToSend.push_back(&dmSelf);
        } else {
            dmsToSend.push_back(&dmSelf);
            dmsToSend.push_back(&dmRcpt);
        }
    } else {
        dmsToSend.push_back(&dmRcpt);
    }

    Value ret;

    BOOST_FOREACH(entry *dm, dmsToSend) {
        entry v;
        if( !createSignedUserpost(v, strFrom, k,
                                  USERPOST_FLAG_DM,
                                  "", dm, NULL,
                                  std::string(""), 0) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

        std::vector<char> buf;
        bencode(std::back_inserter(buf), v);

        std::string errmsg;
        if( !acceptSignedPost(buf.data(),buf.size(),strFrom,k,errmsg,NULL) )
            throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

        if( !copySelf ) {
            // do not send a copy to self, so just store it locally.
            StoredDirectMsg stoDM;
            stoDM.m_fromMe  = true;
            stoDM.m_from    = strFrom;
            stoDM.m_k       = k;
            stoDM.m_text    = strMsg;
            stoDM.m_utcTime = v["userpost"]["time"].integer();

            LOCK(cs_twister);
            m_users[strFrom].m_directmsg[strTo].push_back(stoDM);
        }

        torrent_handle h = startTorrentUser(strFrom, true);
        if( h.is_valid() ) {
            h.add_piece(k++,buf.data(),buf.size());
        }

        hexcapePost(v);
        ret = entryToJson(v);
    }
    return ret;
}

Value newrtmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "newrtmsg <username> <k> <rt_v_object> [comment]\n"
            "Post a new RT to swarm");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strK        = boost::lexical_cast<std::string>(k);
    entry  vrt         = jsonToEntry(params[2].get_obj());
    unHexcapePost(vrt);
    entry const *rt    = vrt.find_key("userpost");
    entry const *sig_rt= vrt.find_key("sig_userpost");
    string strComment  = params.size() > 3 ? params[3].get_str() : "";

    entry v;
    // [MF] Warning: findLastPublicPostLocalUser requires that we follow ourselves
    int lastk = findLastPublicPostLocalUser(strUsername);
    if( lastk >= 0 )
        v["userpost"]["lastk"] = lastk;

    if( !createSignedUserpost(v, strUsername, k,
                              USERPOST_FLAG_RT,
                              strComment, rt, sig_rt,
                              std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername, true);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        dhtPutData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), 1);
    }

    // post to dht as well
    dhtPutData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), 1);
    dhtPutData(strUsername, string("status"), false,
                     v, strUsername, GetAdjustedTime(), k);

    // notification to keep track of RTs of the original post
    if( rt ) {
        string rt_user = rt->find_key("n")->string();
        string rt_k    = boost::lexical_cast<std::string>(rt->find_key("k")->integer());
        dhtPutData(rt_user, string("rts")+rt_k, true,
                         v, strUsername, GetAdjustedTime(), 0);
    }
    //look for hashtags and mentions in comment
    dispatchHM(strComment, strUsername, v);

    hexcapePost(v);
    return entryToJson(v);
}


Value newfavmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "newfavmsg <username> <k> <fav_v_object> [private=false] [comment=''] \n"
            "Add a post to swarm as a favorite");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strK        = boost::lexical_cast<std::string>(k);
    string strComment  = (params.size() > 4) ? params[4].get_str() : "";
    entry  vfav        = jsonToEntry(params[2].get_obj());
    bool isPriv        = (params.size() > 3) ? params[3].get_bool() : false;
    unHexcapePost(vfav);
    entry const *fav    = vfav.find_key("userpost");
    entry const *sig_fav= vfav.find_key("sig_userpost");

    entry v;

    if (isPriv)
    {
        //comments for private favs should be private too...
        vfav["comment"] = strComment;
        std::vector<char> payloadbuf;
        bencode(std::back_inserter(payloadbuf), vfav);
        std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

        entry pfav;
        if( !createDirectMessage(pfav, strUsername, strMsgData) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "error encrypting to pubkey of destination user");

        if( !createSignedUserpost(v, strUsername, k,
                                  USERPOST_FLAG_P_FAV,
                                  "", &pfav, NULL,
                                  std::string(""), 0) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");
    }
    else if( !createSignedUserpost(v, strUsername, k,
                                   USERPOST_FLAG_FAV,
                                   strComment, fav, sig_fav,
                                   std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername, true);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    }
    //look for mentions and hashtags in comment if it isn't private...
    if (!isPriv)
        dispatchHM(strComment, strUsername, v);

    hexcapePost(v);
    return entryToJson(v);
}

Value getposts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "getposts <count> '[{\"username\":username,\"max_id\":max_id,\"since_id\":since_id},...]' [allowed_flags=~2] [required_flags=0]\n"
            "get posts from users\n"
            "max_id and since_id may be omited\n"
            "(optional) allowed/required flags are bitwise fields (1=RT,2=DM,4=FAV,12=PFAV)");

    int count          = params[0].get_int();
    Array users        = params[1].get_array();
    int allowed_flags  = (params.size() > 2) ? params[2].get_int() : USERPOST_FLAG_HOME;
    int required_flags = (params.size() > 3) ? params[3].get_int() : 0;

    std::multimap<int64,entry> postsByTime;

    for( unsigned int u = 0; u < users.size(); u++ ) {
        Object user = users[u].get_obj();
        string strUsername;
        int max_id = std::numeric_limits<int>::max();
        int since_id = -1;

        for (Object::const_iterator i = user.begin(); i != user.end(); ++i) {
            if( i->name_ == "username" ) strUsername = i->value_.get_str();
            if( i->name_ == "max_id" ) max_id = i->value_.get_int();
            if( i->name_ == "since_id" ) since_id = i->value_.get_int();
        }

        torrent_handle h = getTorrentUser(strUsername);
        if( h.is_valid() ){
            std::vector<std::string> pieces;
            h.get_pieces(pieces, count, max_id, since_id, allowed_flags, required_flags);

            BOOST_FOREACH(string const& piece, pieces) {
                lazy_entry v;
                int pos;
                libtorrent::error_code ec;
                if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0 &&
                    v.type() == lazy_entry::dict_t) {
                    lazy_entry const* post = v.dict_find_dict("userpost");
                    int64 time = post->dict_find_int_value("time",-1);

                    if(time == -1 || time > GetAdjustedTime() + MAX_TIME_IN_FUTURE ) {
                        printf("getposts: ignoring far-future message by '%s'\n", strUsername.c_str());
                    }

                    entry vEntry;
                    vEntry = v;
                    hexcapePost(vEntry);
                    postsByTime.insert( pair<int64,entry>(time, vEntry) );
                }
            }
        }
    }

    Array ret;
    std::multimap<int64,entry>::reverse_iterator rit;
    for (rit=postsByTime.rbegin(); rit!=postsByTime.rend() && (int)ret.size() < count; ++rit) {
        ret.push_back( entryToJson(rit->second) );
    }

    {
        LOCK(cs_spamMsg);
        // we must agree on an acceptable level here
        // what about one every eight hours? (not cumulative)
        if( m_receivedSpamMsgStr.length() && GetAdjustedTime() > m_lastSpamTime + (8*3600) ) {
            m_lastSpamTime = GetAdjustedTime();

            entry v = formatSpamPost(m_receivedSpamMsgStr, m_receivedSpamUserStr, 0, m_receivedSpamHeight);
            ret.insert(ret.begin(),entryToJson(v));

            m_receivedSpamMsgStr = "";
            m_receivedSpamUserStr = "";
        }
    }

    return ret;
}

Value getdirectmsgs(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "getdirectmsgs <localuser> <count_per_user> '[{\"username\":username,\"max_id\":max_id,\"since_id\":since_id},...]'\n"
            "get (locally stored) decrypted direct messages sent/received by user <localuser>\n"
            "max_id and since_id may be omited. up to <count_per_user> are returned for each remote user.");

    string strUsername = params[0].get_str();
    int count          = params[1].get_int();
    Array remoteusers  = params[2].get_array();

    Object ret;
    for( unsigned int u = 0; u < remoteusers.size(); u++ ) {
        Object remoteUser = remoteusers[u].get_obj();
        string remoteUsername;
        int max_id = std::numeric_limits<int>::max();
        int since_id = -1;

        for (Object::const_iterator i = remoteUser.begin(); i != remoteUser.end(); ++i) {
            if( i->name_ == "username" ) remoteUsername = i->value_.get_str();
            if( i->name_ == "max_id" ) max_id = i->value_.get_int();
            if( i->name_ == "since_id" ) since_id = i->value_.get_int();
        }

        LOCK(cs_twister);
        if( remoteUsername.size() && m_users.count(strUsername) &&
            m_users[strUsername].m_directmsg.count(remoteUsername) ){
            std::vector<StoredDirectMsg> &dmsFromToUser = m_users[strUsername].m_directmsg[remoteUsername];
            max_id = std::min( max_id, (int)dmsFromToUser.size()-1);
            since_id = std::max( since_id, max_id - count );

            Array userMsgs;
            for( int i = std::max(since_id+1,0); i <= max_id; i++) {
                Object dmObj;
                dmObj.push_back(Pair("id",i));
                dmObj.push_back(Pair("time",dmsFromToUser.at(i).m_utcTime));
                dmObj.push_back(Pair("text",dmsFromToUser.at(i).m_text));
                dmObj.push_back(Pair("fromMe",dmsFromToUser.at(i).m_fromMe));
                dmObj.push_back(Pair("from",dmsFromToUser.at(i).m_from));
                dmObj.push_back(Pair("k",dmsFromToUser.at(i).m_k));
                userMsgs.push_back(dmObj);
            }
            if( userMsgs.size() ) {
                ret.push_back(Pair(remoteUsername,userMsgs));
            }
        }
    }

    return ret;
}

Value getmentions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3 )
        throw runtime_error(
            "getmentions <localuser> <count> '{\"max_id\":max_id,\"since_id\":since_id}'\n"
            "get (locally stored) mentions to user <localuser> by users followed.\n"
            "(use 'dhtget user mention m' for non-followed mentions)\n"
            "max_id and since_id may be omited. up to <count> posts are returned.");

    string strUsername = params[0].get_str();
    int count          = params[1].get_int();

    int max_id = std::numeric_limits<int>::max();
    int since_id = -1;

    if( params.size() >= 3 ) {
        Object optParms    = params[2].get_obj();
        for (Object::const_iterator i = optParms.begin(); i != optParms.end(); ++i) {
            if( i->name_ == "max_id" ) max_id = i->value_.get_int();
            if( i->name_ == "since_id" ) since_id = i->value_.get_int();
        }
    }

    Array ret;

    LOCK(cs_twister);
    if( strUsername.size() && m_users.count(strUsername) ) {
        const std::vector<libtorrent::entry> &mentions = m_users[strUsername].m_mentionsPosts;
        max_id = std::min( max_id, (int)mentions.size()-1);
        since_id = std::max( since_id, max_id - count );

        for( int i = std::max(since_id+1,0); i <= max_id; i++) {
            const entry *post = mentions.at(i).find_key("userpost");
            if( post && post->type() == entry::dictionary_t ) {
                const entry *ptime = post->find_key("time");
                if( ptime && ptime->type() == entry::int_t ) {
                    int64 time = ptime->integer();

                    if(time <= 0 || time > GetAdjustedTime() + MAX_TIME_IN_FUTURE ) {
                        printf("getmentions: ignoring far-future post\n");
                    } else {
                        entry vEntry;
                        vEntry = mentions.at(i);
                        hexcapePost(vEntry);
                        vEntry["id"] = i;
                        ret.push_back(entryToJson(vEntry));
                    }
                }
            }
        }
    }

    return ret;
}

Value getfavs(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3 )
        throw runtime_error(
            "getfavs <localuser> <count> '{\"max_id\":max_id,\"since_id\":since_id}'\n"
            "Get favorite posts (private favorites are included) of localuser\n"
            "max_id and since_id may be omited. up to <count> posts are returned.");

    string strUsername  = params[0].get_str();
    int cnt             = params[1].get_int();
    int max_id = std::numeric_limits<int>::max();
    int since_id = -1;

    if( params.size() > 2 ) {
        Object optParms    = params[2].get_obj();
        for (Object::const_iterator i = optParms.begin(); i != optParms.end(); ++i) {
            if( i->name_ == "max_id" ) max_id = i->value_.get_int();
            if( i->name_ == "since_id" ) since_id = i->value_.get_int();
        }
    }

    multimap<int64,entry> postsByTime;

    torrent_handle h = startTorrentUser(strUsername, true);
    if( h.is_valid() ) {
        std::vector<std::string> pieces;
        h.get_pieces(pieces, cnt, max_id, since_id, USERPOST_FLAG_P_FAV, USERPOST_FLAG_FAV);

        BOOST_FOREACH(string const& piece, pieces) {
            lazy_entry v;
            int pos;
            libtorrent::error_code ec;
            if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0 &&
                v.type() == lazy_entry::dict_t) {
                lazy_entry const* post = v.dict_find_dict("userpost");
                if (!post || post->type() != lazy_entry::dict_t)
                    continue;
                int64 time = post->dict_find_int_value("time",-1);

                if(time == -1 || time > GetAdjustedTime() + MAX_TIME_IN_FUTURE ) {
                    printf("getposts: ignoring far-future message by '%s'\n", strUsername.c_str());
                    continue;
                }

                lazy_entry const* fav = post->dict_find_dict("fav");
                lazy_entry const* pfav = post->dict_find_dict("pfav");
                if (fav && fav->type() == lazy_entry::dict_t)
                {
                    entry vEntry;
                    vEntry = v;
                    vEntry["isPrivate"] = false;
                    hexcapePost(vEntry);
                    postsByTime.insert( pair<int64,entry>(time, vEntry) );
                }
                else if (pfav && pfav->type() == lazy_entry::dict_t)
                {
                    ecies_secure_t sec;
                    sec.key = pfav->dict_find_string_value("key");
                    sec.mac = pfav->dict_find_string_value("mac");
                    sec.orig = pfav->dict_find_int_value("orig");
                    sec.body = pfav->dict_find_string_value("body");

                    CKey key;
                    CKeyID keyID;
                    if (pwalletMain->GetKeyIdFromUsername(strUsername, keyID) &&
                        pwalletMain->GetKey( keyID, key) ) {
                        /* success: key obtained from wallet */

                        string textOut;
                        if (key.Decrypt(sec, textOut))
                        {
                            lazy_entry dfav;
                            if (lazy_bdecode(textOut.data(), textOut.data()+textOut.size(), dfav, ec, &pos) == 0
                                    && dfav.type() == lazy_entry::dict_t) {
                                        entry vEntry, upst;

                                        upst["fav"] = *(dfav.dict_find_dict("userpost"));
                                        upst["sig_fav"] = dfav.dict_find_string_value("sig_userpost");
                                        upst["n"] = post->dict_find_string_value("n");
                                        upst["k"] = post->dict_find_int_value("k");
                                        upst["msg"] = dfav.dict_find_string_value("comment");
                                        upst["time"] = post->dict_find_int_value("time");
                                        upst["height"] = post->dict_find_int_value("height");

                                        vEntry["isPrivate"] = true;
                                        vEntry["userpost"] = upst;

                                        hexcapePost(vEntry);
                                        postsByTime.insert( pair<int64,entry>(time, vEntry) );

                                }
                        }
                    } else
                      printf("getfavs: no key for user '%s'\n", strUsername.c_str());
                }
            }
        }
    }

    Array ret;
    std::multimap<int64,entry>::reverse_iterator rit;
    for (rit=postsByTime.rbegin(); rit!=postsByTime.rend() && (int)ret.size() < cnt; ++rit) {
        ret.push_back( entryToJson(rit->second) );
    }

    return ret;
}

Value setspammsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "setspammsg <username> <msg> [add|remove|replace]\n"
            "Set spam message attached to generated blocks\n"
            "replace is default operation.");

    string strUsername = params[0].get_str();
    string strMsg      = params[1].get_str();
    string strOp       = params.size() == 3 ? params[2].get_str() : "replace";

    int spamMsgUtf8Size = utf8::num_characters(strMsg.begin(), strMsg.end());
    if (spamMsgUtf8Size < 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "spam message invalid utf8");
    if (spamMsgUtf8Size == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "empty spam message");
    if (spamMsgUtf8Size > MAX_SPAM_MSG_SIZE)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "spam message too big");

    Array ret;
    {
        LOCK(cs_spamMessages);
        strSpamUser    = strUsername;
        if (strOp == "add")
        {
            spamMessages.push_back(strMsg);
            spamMessages.unique();
        }
        else if (strOp == "remove")
            spamMessages.remove(strMsg);
        else if (strOp == "replace")
        {
            spamMessages.clear();
            spamMessages.push_back(strMsg);
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown operation");

        BOOST_FOREACH(string msg, spamMessages)
            ret.push_back(msg);
    }

    return ret;
}

Value getspammsg(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "getspammsg\n"
            "get spam message attached to generated blocks");

    Array ret;
    ret.push_back(strSpamUser);

    {
        LOCK(cs_spamMessages);
        BOOST_FOREACH(string msg, spamMessages)
            ret.push_back(msg);
    }
    //if spamMessages is empty, use default message...
    if (ret.size() == 1)
        ret.push_back(strSpamMessage);

    return ret;
}

Value setpreferredspamlang(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "setpreferredspamlang <langcode>\n"
            "Set preferred spam language (or 'none')");

    string strLangCode = params[0].get_str();

    if (strLangCode == "none") {
        m_preferredSpamLang = "[]";
    } else {
        if( strLangCode.find("[") == string::npos ) {
            m_preferredSpamLang = "[" + strLangCode + "]";
        } else {
            m_preferredSpamLang = strLangCode;
        }
    }

    return Value();
}

Value getpreferredspamlang(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "getpreferredspamlang\n"
            "get preferred spam language");

    return Value(m_preferredSpamLang);
}

Value follow(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "follow <username> [follow_username1,follow_username2,...]\n"
            "start following users");

    string localUser = params[0].get_str();
    Array users      = params[1].get_array();

    for( unsigned int u = 0; u < users.size(); u++ ) {
        string username = users[u].get_str();
        torrent_handle h = startTorrentUser(username, true);

        if( h.is_valid() ) {
            LOCK(cs_twister);
            m_users[localUser].m_following.insert(username);
        }
    }

    return Value();
}

Value unfollow(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "unfollow <username> [unfollow_username1,unfollow_username2,...]\n"
            "stop following users");

    string localUser = params[0].get_str();
    Array users      = params[1].get_array();

    LOCK(cs_twister);
    for( unsigned int u = 0; u < users.size(); u++ ) {
        string username = users[u].get_str();

        if( m_users.count(localUser) &&
            m_users[localUser].m_following.count(username) ) {
            m_users[localUser].m_following.erase(username);
        }
    }

    return Value();
}

Value getfollowing(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "getfollowing <username>\n"
            "get list of users we follow");

    string localUser = params[0].get_str();

    Array ret;
    LOCK(cs_twister);
    if( m_users.count(localUser) ) {
        BOOST_FOREACH(string username, m_users[localUser].m_following) {
            ret.push_back(username);
        }
    }
    return ret;
}

Value getlasthave(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getlasthave <username> | <groupname> [user1,user2...]\n"
            "get last 'have' (higher post number) of each user local user follows.\n"
            "if a groupname with an array is given, only those users' last 'have' values will be returned.");

    std::set<std::string> following;

    string localUser = params[0].get_str();
    if (params.size() > 1)
    {
        Array userlist = params[1].get_array();
        for (unsigned int i = 0; i < userlist.size(); i++)
            following.insert(userlist[i].get_str());
    }
    else
    {
        LOCK(cs_twister);
        if( m_users.count(localUser) )
            following = m_users[localUser].m_following;
    }

    Object ret;
    BOOST_FOREACH(string username, following) {
        ret.push_back(Pair(username,torrentLastHave(username)));
    }

    return ret;
}

Value getnumpieces(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "getnumpieces <username>\n"
            "get number of posts already downloaded for each user user we follow");

    string localUser = params[0].get_str();

    std::set<std::string> following;
    {
        LOCK(cs_twister);
        if( m_users.count(localUser) )
            following = m_users[localUser].m_following;
    }

    Object ret;
    BOOST_FOREACH(string username, following) {
        ret.push_back(Pair(username,torrentNumPieces(username)));
    }

    return ret;
}

Value listusernamespartial(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() < 2 || params.size() > 3))
        throw runtime_error(
            "listusernamespartial <username_starts_with> <count> [exact_match=false]\n"
            "get list of usernames starting with");

    string userStartsWith = params[0].get_str();
    size_t count          = params[1].get_int();
    bool   exact_match    = false;
    if( params.size() > 2 )
        exact_match       = params[2].get_bool();

    set<string> retStrings;

    // priorize users in following list
    {
        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CKeyID, CKeyMetadata)& item, pwalletMain->mapKeyMetadata) {
            LOCK(cs_twister);
            BOOST_FOREACH(const string &user, m_users[item.second.username].m_following) {
                if( (exact_match && userStartsWith.size() != user.size()) ||
                    userStartsWith.size() > user.size() ) {
                    continue;
                }
                int toCompare = userStartsWith.size();
                if( memcmp( user.data(), userStartsWith.data(), toCompare ) == 0 )
                    retStrings.insert( user );
                if( retStrings.size() >= count )
                    break;
            }
        }
    }

    pblocktree->GetNamesFromPartial(userStartsWith, retStrings, count);

    Array ret;
    BOOST_FOREACH(string username, retStrings) {
        ret.push_back(username);
    }

    return ret;
}

Value rescandirectmsgs(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "rescandirectmsgs <username>\n"
            "rescan all streams of users we follow for new and old directmessages");

    string localUser = params[0].get_str();

    std::set<std::string> following;
    {
        LOCK(cs_twister);
        following = m_users[localUser].m_following;
    }

    BOOST_FOREACH(string username, following) {
        torrent_handle h = getTorrentUser(username);
        if( h.is_valid() ){
            h.recheck_pieces(USERPOST_FLAG_DM);
        }
    }

    return Value();
}

Value recheckusertorrent(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "recheckusertorrent <username>\n"
            "recheck all posts in a given torrent. this may be useful if\n"
            "post validation rules became stricter");

    string localUser = params[0].get_str();

    torrent_handle h = getTorrentUser(localUser);
    if( h.is_valid() ){
        h.force_recheck();
    }

    return Value();
}

Value gettrendinghashtags(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "gettrendinghashtags <count>\n"
            "obtain list of trending hashtags");

    size_t count = params[0].get_int();

    std::map<double,std::string> sortedHashtags;
    {
        LOCK(cs_seenHashtags);
        BOOST_FOREACH(const PAIRTYPE(std::string,double)& item, m_seenHashtags) {
            sortedHashtags[item.second]=item.first;
        }
    }

    Array ret;
    BOOST_REVERSE_FOREACH(const PAIRTYPE(double, std::string)& item, sortedHashtags) {
        if( ret.size() >= count )
            break;
        ret.push_back(item.second);
    }

    return ret;
}

Value getspamposts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "getspamposts <count> [max_id] [since_id]\n"
            "get spam posts from blockchain\n"
            "max_id and since_id may be omited (or -1)");

    int count          = params[0].get_int();
    int max_id         = getBestHeight();
    if (params.size() > 1 && params[1].get_int() != -1)
        max_id = std::min(params[1].get_int(), max_id);
    int since_id       = -1;
    if (params.size() > 2)
        since_id = std::max(params[2].get_int(), since_id);

    Array ret;
    std::string lastMsg;

    for( int height = max_id; height > since_id && (int)ret.size() < count; height-- ) {
        CBlockIndex* pblockindex = FindBlockByHeight(height);
        CBlock block;
        ReadBlockFromDisk(block, pblockindex);

        const CTransaction &tx = block.vtx[0];
        if( tx.IsSpamMessage() ) {
            std::string spamMessage = tx.message.ExtractPushDataString(0);
            std::string spamUser = tx.userName.ExtractPushDataString(0);

            // remove consecutive duplicates
            if( spamMessage == lastMsg)
                continue;
            lastMsg = spamMessage;

            entry v = formatSpamPost(spamMessage, spamUser,
                                     block.GetBlockTime(), height);
            ret.insert(ret.begin(),entryToJson(v));
        }
    }

    return ret;
}

Value torrentstatus(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "torrentstatus <username>\n"
            "report torrent status");

    string localUser = params[0].get_str();

    torrent_handle h = getTorrentUser(localUser);
    if( !h.is_valid() ){
        return Value();
    }

    torrent_status status = h.status();

    Object result;
    result.push_back(Pair("state", status.state));
    result.push_back(Pair("paused", status.paused));
    result.push_back(Pair("auto_managed", status.auto_managed));
    result.push_back(Pair("num_peers", status.num_peers));
    result.push_back(Pair("list_peers", status.list_peers));
    result.push_back(Pair("connect_candidates", status.connect_candidates));
    result.push_back(Pair("num_connections", status.num_connections));
    result.push_back(Pair("num_complete", status.num_complete));
    result.push_back(Pair("num_pieces", status.num_pieces));
    string bitfield;
    for(std::size_t i = 0; i < status.pieces.size(); i++) {
        bitfield.append( status.pieces[i]?"1":"0" );
    }
    result.push_back(Pair("bitfield", bitfield));
    result.push_back(Pair("has_incoming", status.has_incoming));
    result.push_back(Pair("priority", status.priority));
    result.push_back(Pair("queue_position", status.queue_position));

    Array peers;
    std::vector<peer_info> peerInfos;
    h.get_peer_info(peerInfos);
    BOOST_FOREACH(const peer_info &p, peerInfos) {
        Object info;
        info.push_back(Pair("addr", p.ip.address().to_string() + ":" +
                            boost::lexical_cast<std::string>(p.ip.port())));
        char flags[10];
        sprintf(flags,"0x%x",p.flags);
        info.push_back(Pair("flags",flags));
        info.push_back(Pair("connection_type", p.connection_type));
        info.push_back(Pair("download_queue_length", p.download_queue_length));
        info.push_back(Pair("failcount", p.failcount));
        bitfield = "";
        for(std::size_t i = 0; i < p.pieces.size(); i++) {
            bitfield.append( p.pieces[i]?"1":"0" );
        }
        info.push_back(Pair("bitfield", bitfield));
        peers.push_back(info);
    }
    result.push_back(Pair("peers", peers));

    return result;
}

class TextSearch
{
public:
    enum search_mode {
        TEXTSEARCH_EXACT,
        TEXTSEARCH_ALL,
        TEXTSEARCH_ANY
    };

    TextSearch(std::string const &keyword, libtorrent::entry const &params);

    bool matchText(std::string msg);
    bool matchTime(int64_t time);
    libtorrent::lazy_entry const* matchRawMessage(std::string const &rawMessage, libtorrent::lazy_entry &v);

private:
    std::vector<std::string> keywords;
    search_mode mode;
    bool caseInsensitive;
    int64_t timeMin, timeMax;
    std::string username;
};

TextSearch::TextSearch(string const &keyword, entry const &params) :
    mode(TEXTSEARCH_EXACT),
    caseInsensitive(false),
    timeMin(numeric_limits<int64_t>::min()),
    timeMax(numeric_limits<int64_t>::max())
{
    entry const *pMode = params.find_key("mode");
    if( pMode && pMode->type() == entry::string_t ) {
        string strMode = pMode->string();
        if( strMode == "all" ) {
            mode = TEXTSEARCH_ALL;
        } else if( strMode == "any" ) {
            mode = TEXTSEARCH_ANY;
        }
    }

    entry const *pCase = params.find_key("case");
    caseInsensitive = pCase && pCase->type() == entry::string_t && pCase->string() == "insensitive";

    int64_t now = GetAdjustedTime();

    entry const *pAgeMin = params.find_key("agemin");
    if( pAgeMin && pAgeMin->type() == entry::int_t ) {
        timeMax = now - pAgeMin->integer() * 24*60*60;
    }

    entry const *pAgeMax = params.find_key("agemax");
    if( pAgeMax && pAgeMax->type() == entry::int_t ) {
        timeMin = now - pAgeMax->integer() * 24*60*60;
    }

    entry const *pUsername = params.find_key("username");
    if( pUsername && pUsername->type() == entry::string_t ) {
        username = pUsername->string();
    }

    if( mode == TEXTSEARCH_EXACT ) {
        keywords.push_back( keyword );
    } else {
        stringstream stream( keyword );
        string word;
        while( getline(stream, word, ' ') ) {
            if( !word.empty() ) {
                keywords.push_back( word );
            }
        }
    }

    if( caseInsensitive ) {
        for( vector<string>::iterator it=keywords.begin(); it != keywords.end(); ++it ) {
#ifdef HAVE_BOOST_LOCALE
            *it = boost::locale::to_lower(*it);
#else
            boost::algorithm::to_lower(*it);
#endif
        }
    }
}

bool TextSearch::matchText(string msg)
{
    if( keywords.size() == 0 ) {
        return false;
    }

    if( caseInsensitive ) { // that is why msg is passed by value
#ifdef HAVE_BOOST_LOCALE
        msg = boost::locale::to_lower(msg);
#else
        boost::algorithm::to_lower(msg);
#endif
    }

    switch( mode ) {
    case TEXTSEARCH_EXACT:
           return msg.find(keywords[0]) != string::npos;
    case TEXTSEARCH_ALL:
        for( vector<string>::const_iterator it=keywords.begin(); it != keywords.end(); ++it ) {
            if( msg.find(*it) == string::npos ) {
                return false;
            }
        }
        return true;
    case TEXTSEARCH_ANY:
        for( vector<string>::const_iterator it=keywords.begin(); it != keywords.end(); ++it ) {
            if( msg.find(*it) != string::npos ) {
                return true;
            }
        }
        return false;
    }
    return false;
}

inline bool TextSearch::matchTime(int64_t time)
{
    return time >= timeMin && time <= timeMax;
}

lazy_entry const* TextSearch::matchRawMessage(string const &rawMessage, lazy_entry &v)
{
    if( keywords.size() == 0 ) {
        return 0;
    }
    // fast check
    if( !caseInsensitive && mode != TEXTSEARCH_ANY && rawMessage.find(keywords[0]) == string::npos ) {
        return 0;
    }

    int pos;
    libtorrent::error_code ec;
    if (lazy_bdecode(rawMessage.data(), rawMessage.data()+rawMessage.size(), v, ec, &pos) == 0 &&
        v.type() == lazy_entry::dict_t) {
        lazy_entry const* vv = v.dict_find_dict("v");
        lazy_entry const* post = vv ? vv->dict_find_dict("userpost") : v.dict_find_dict("userpost");
        if( post ) {
            lazy_entry const* rt = post->dict_find_dict("rt");
            lazy_entry const* p = rt ? rt : post;
            string comment;
            if (rt)
                comment = post->dict_find_string_value("msg");

            if( username.length() ) {
                string user = p->dict_find_string_value("n");
                string rtuser;
                if (rt)
                    rtuser = post->dict_find_string_value("n");
                if( user != username && (!comment.size() || rtuser != username)) {
                    return 0;
                }
            }

            int64_t time = p->dict_find_int_value("time");
            int64_t rttime = 0;
            if (comment.size())
                rttime = post->dict_find_int_value("time");
            if( !matchTime(time) && (!rttime || !matchTime(rttime)) ) {
                return 0;
            }

            string msg = p->dict_find_string_value("msg");
            if (matchText(msg) || matchText(comment))
                //for RTable results, it returns signed post instead of userpost
                return vv ? vv : &v;
        }
    }
    return 0;
}

Value search(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "search <scope> <text> <count> ['{\"username\":username,\"mode\":\"exact\"|\"all\"|\"any\",\"case\":\"sensitive\"|\"insensitive\",\"agemin\":agemin,\"agemax\":agemax}']\n"
            "search text in available data\n"
            "<scope> is data area: messages, directmsgs, profiles, users, hashtags, favorites\n"
            "<text> is a phrase to search\n"
            "up to <count> entries are returned\n"
            "<username> in messages scope is optional and allows to search in username's messages only\n"
            "<username> in directmsgs scope is required and sets whose conversation to search\n"
            "\"mode\" and \"case\" are search mode options\n"
            "\"agemin\" and \"agemax\" (days) are message date filter\n"
            "\"mode\", \"case\", \"agemin\", and \"agemax\" are optional");

    string scope    = params[0].get_str();
    string keyword  = params[1].get_str();
    int    count    = params[2].get_int();
    entry  options  = params.size()==4 ? jsonToEntry(params[3].get_obj()) : entry();
    string username;

    if( keyword.size() == 0 ) {
        throw runtime_error("Empty <text> parameter");
    }

    entry const *pUsername = options.find_key("username");
    if( pUsername && pUsername->type() == entry::string_t ) {
        username = pUsername->string();
    }

    Array ret;

    if( scope == "messages" ) {
        // search public messages
        std::map< pair<std::string,int>, pair<int64,entry> > posts;
        lazy_entry v;

        TextSearch searcher(keyword, options);

        // search public messages in torrents
        {
            LOCK(cs_twister);

            std::map<std::string,torrent_handle> users;

            if( username.size() == 0 ) {
                users = m_userTorrent;
            } else {
                if( m_userTorrent.count(username) )
                    users[username] = m_userTorrent[username];
            }

            BOOST_FOREACH(const PAIRTYPE(std::string,torrent_handle)& item, users) {
                std::vector<std::string> pieces;
                item.second.get_pieces(pieces, std::numeric_limits<int>::max(), std::numeric_limits<int>::max(), -1, USERPOST_FLAG_HOME, 0);

                BOOST_FOREACH(string const& piece, pieces) {
                    lazy_entry const* p = searcher.matchRawMessage(piece, v);
                    if( p ) {
                        const lazy_entry *up = p->dict_find_dict("userpost");
                        if (up)
                        {
                            string n = up->dict_find_string_value("n");
                            int k = up->dict_find_int_value("k");
                            int64 time = up->dict_find_int_value("time",-1);

                            entry vEntry;
                            vEntry = *p;
                            hexcapePost(vEntry);

                            posts[pair<std::string,int>(n,k)] = pair<int64,entry>(time,vEntry);
                        }
                    }
                }
            }
        }

        // search messages in dht
        boost::shared_ptr<session> ses(m_ses);
        if( ses )
        {
            entry data = ses->dht_getLocalData();

            if( data.type() == entry::dictionary_t ) {

                for (entry::dictionary_type::const_iterator i = data.dict().begin(); i != data.dict().end(); ++i) {
                    if ( i->second.type() != entry::list_t )
                        continue;
                    for (entry::list_type::const_iterator j = i->second.list().begin(); j != i->second.list().end(); ++j) {
                        entry const* key_p = j->find_key("p");
                        if( key_p ) {
                            string str_p = key_p->string();
                            lazy_entry const* p = searcher.matchRawMessage(str_p, v);
                            if( p ) {
                                const lazy_entry *up = p->dict_find_dict("userpost");
                                if (up)
                                {
                                    string n = up->dict_find_string_value("n");
                                    int k = up->dict_find_int_value("k");
                                    pair<std::string,int> post_id(n,k);
                                    if( posts.count(post_id) == 0 ) {
                                        int64 time = up->dict_find_int_value("time",-1);

                                        entry vEntry;
                                        vEntry = *p;
                                        hexcapePost(vEntry);

                                        posts[post_id] = pair<int64,entry>(time,vEntry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        std::multimap<int64,entry> postsByTime;
        BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(std::string,int),PAIRTYPE(int64,entry))& item, posts) {
            postsByTime.insert(item.second);
        }

        std::multimap<int64,entry>::reverse_iterator rit;
        for (rit=postsByTime.rbegin(); rit!=postsByTime.rend() && (int)ret.size() < count; ++rit) {
            ret.push_back( entryToJson(rit->second) );
        }

    } else if( scope == "directmsgs" ) {
        // search direct messages
        if( m_users.count(username) ) {
            std::multimap<int64,entry> postsByTime;

            TextSearch searcher(keyword, options);

            {
                LOCK(cs_twister);

                BOOST_FOREACH(const PAIRTYPE(std::string,std::vector<StoredDirectMsg>)& list, m_users[username].m_directmsg) {
                    string remoteUser = list.first;
                    BOOST_FOREACH(const StoredDirectMsg& item, list.second) {
                        if( searcher.matchText(item.m_text) ) {
                            int64_t time = item.m_utcTime;
                            if( searcher.matchTime(time) ) {
                                entry vEntry;
                                vEntry["remoteUser"] = remoteUser;
                                vEntry["text"] = item.m_text;
                                vEntry["time"] = time;
                                vEntry["fromMe"] = item.m_fromMe;
                                vEntry["from"] = item.m_from;
                                vEntry["k"] = item.m_k;
                                hexcapePost(vEntry);
                                postsByTime.insert( pair<int64,entry>(time, vEntry) );
                            }
                        }
                    }
                }
            }

            std::multimap<int64,entry>::reverse_iterator rit;
            for (rit=postsByTime.rbegin(); rit!=postsByTime.rend() && (int)ret.size() < count; ++rit) {
                ret.push_back( entryToJson(rit->second) );
            }
        }

    } else if( scope == "profiles" ) {
        // search dht profiles
        boost::shared_ptr<session> ses(m_ses);
        if( ses )
        {
            entry data = ses->dht_getLocalData();
            std::map<string,entry> users;

            TextSearch searcher(keyword, options);

            for (entry::dictionary_type::const_iterator i = data.dict().begin(); i != data.dict().end(); ++i) {
                if ( i->second.type() != entry::list_t )
                    continue;
                for (entry::list_type::const_iterator j = i->second.list().begin(); j != i->second.list().end(); ++j) {
                    string str_p = j->find_key("p")->string();
                    lazy_entry p;
                    int pos;
                    libtorrent::error_code err;
                    if( lazy_bdecode(str_p.data(), str_p.data() + str_p.size(), p, err, &pos) != 0 ||
                        p.type() != lazy_entry::dict_t) {
                        continue;
                    }

                    lazy_entry const* target = p.dict_find_dict("target");
                    if( target ) {
                        string resource = target->dict_find_string_value("r");
                        if( resource == "profile" ) {
                            lazy_entry const* v = p.dict_find_dict("v");
                            if( v ) {
                                if( searcher.matchText(v->dict_find_string_value("bio")) ||
                                    searcher.matchText(v->dict_find_string_value("fullname")) ||
                                    searcher.matchText(v->dict_find_string_value("location")) ||
                                    searcher.matchText(v->dict_find_string_value("url")) ) {

                                    string n = target->dict_find_string_value("n");
                                    entry vEntry;
                                    vEntry = *v;
                                    users.insert(pair<string,entry>(n,vEntry));
                                }
                            }
                        }
                    }
                }
            }

            std::map<string,entry>::iterator it;
            for (it=users.begin(); it!=users.end() && (int)ret.size() < count; ++it) {
                entry user;
                user["username"] = it->first;
                user["profile"] = it->second;
                ret.push_back( entryToJson(user) );
            }
        }

    } else if( scope == "users" ) {
        // search users (blockchain)
        // @todo: there should be a faster way
        std::multimap<string::size_type,std::string> usernamesByLength;

        boost::algorithm::to_lower(keyword);

        string allowed = "abcdefghijklmnopqrstuvwxyz0123456789_";
        for( int i = 0; i < (int)allowed.size(); ++i ) {
            set<string> usernames;
            string prefix(1, allowed[i]);
            pblocktree->GetNamesFromPartial(prefix, usernames, std::numeric_limits<int>::max());

            BOOST_FOREACH(string username, usernames) {
                if( username.find(keyword) != string::npos ) {
                    usernamesByLength.insert( pair<string::size_type,std::string>(username.size(), username) );
                }
            }
        }

        std::multimap<string::size_type,std::string>::iterator it;
        for (it=usernamesByLength.begin(); it!=usernamesByLength.end() && (int)ret.size() < count; ++it) {
            ret.push_back( entryToJson(it->second) );
        }

    } else if( scope == "hashtags" ) {
        // search hashtags
        std::multimap<string::size_type,std::string> hashtagsByLength;

#ifdef HAVE_BOOST_LOCALE
        keyword = boost::locale::to_lower(keyword);
#else
        boost::algorithm::to_lower(keyword);
#endif

        {
            LOCK(cs_seenHashtags);

            BOOST_FOREACH(const PAIRTYPE(std::string,double)& item, m_seenHashtags) {
                if (item.first.find(keyword) != std::string::npos) {
                    hashtagsByLength.insert( pair<string::size_type,std::string>(item.first.size(), item.first) );
                }
            }
        }

        std::multimap<string::size_type,std::string>::iterator it;
        for (it=hashtagsByLength.begin(); it!=hashtagsByLength.end() && (int)ret.size() < count; ++it) {
            ret.push_back( entryToJson(it->second) );
        }

    }
    else if (scope == "favorites")
    {
        std::multimap<int64_t,Value> postsByTime;

        TextSearch searcher(keyword, options);

        set<string> users;
        if (username.size())
            users.insert(username);
        else
        {
            for (map<string,torrent_handle>::const_iterator it = m_userTorrent.begin(); it != m_userTorrent.end(); ++it)
                users.insert(it->first);
        }

        BOOST_FOREACH(string user, users)
        {
            Array params;
            params.push_back(user);
            params.push_back(INT_MAX);
            Array favs = getfavs(params, false).get_array();
            for (int i = 0; i < (int)favs.size(); i++)
            {
                entry favp = jsonToEntry(favs[i]);
                entry *favu = favp.find_key("userpost");
                if (favu && favu->type() == entry::dictionary_t)
                {
                    entry* commEnt = favu->find_key("msg");
                    string comnt;
                    if (commEnt && commEnt->type() == entry::string_t)
                        comnt = commEnt->string();

                    entry *favEnt = favu->find_key("fav");
                    string msg;
                    if (favEnt)
                        msg = favEnt->find_key("msg")->string();

                    if( searcher.matchText(msg) || searcher.matchText(comnt) )
                    {
                        int64_t ft = favu->find_key("time")->integer();
                        if(searcher.matchTime(ft))
                            postsByTime.insert(pair<int64_t,Value>(ft, favs[i]));
                    }
                }
            }
        }

        std::multimap<int64_t,Value>::reverse_iterator rit;
        for (rit = postsByTime.rbegin(); rit != postsByTime.rend() && (int)ret.size() < count; ++rit)
           ret.push_back(rit->second);
    }
    else {
        throw runtime_error("Unknown <scope> value");
    }

    return ret;
}

Object getLibtorrentSessionStatus()
{
    Object obj;
    boost::shared_ptr<session> ses(m_ses);
    if( ses ) {
        session_status stats = ses->status();

        obj.push_back( Pair("ext_addr_net2", stats.external_addr_v4) );

        obj.push_back( Pair("dht_torrents", stats.dht_torrents) );
        obj.push_back( Pair("num_peers", stats.num_peers) );
        obj.push_back( Pair("peerlist_size", stats.peerlist_size) );
        obj.push_back( Pair("num_active_requests", (int)stats.active_requests.size()) );

        obj.push_back( Pair("download_rate", stats.download_rate) );
        obj.push_back( Pair("upload_rate", stats.upload_rate) );
        obj.push_back( Pair("dht_download_rate", stats.dht_download_rate) );
        obj.push_back( Pair("dht_upload_rate", stats.dht_upload_rate) );
        obj.push_back( Pair("ip_overhead_download_rate", stats.ip_overhead_download_rate) );
        obj.push_back( Pair("ip_overhead_upload_rate", stats.ip_overhead_upload_rate) );
        obj.push_back( Pair("payload_download_rate", stats.payload_download_rate) );
        obj.push_back( Pair("payload_upload_rate", stats.payload_upload_rate) );

        obj.push_back( Pair("total_download", stats.total_download) );
        obj.push_back( Pair("total_upload", stats.total_upload) );
        obj.push_back( Pair("total_dht_download", stats.total_dht_download) );
        obj.push_back( Pair("total_dht_upload", stats.total_dht_upload) );
        obj.push_back( Pair("total_ip_overhead_download", stats.total_ip_overhead_download) );
        obj.push_back( Pair("total_ip_overhead_upload", stats.total_ip_overhead_upload) );
        obj.push_back( Pair("total_payload_download", stats.total_payload_download) );
        obj.push_back( Pair("total_payload_upload", stats.total_payload_upload) );
    }
    // @TODO: Is there a way to get some statistics for dhtProxy?
    return obj;
}

Value creategroup(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "creategroup <description> [<groupprivkey>]\n"
            "Create (if <groupprivkey> is omited) a new key pair for group chat and add it to wallet\n"
            "Or import the given <groupprivkey> into wallet\n"
            "Hint: use newgroupinvite to invite yourself\n"
            "Returns the group alias");

    string strDescription = params[0].get_str();
    string privKey;

    if (params.size() == 2)
        privKey = params[1].get_str();
    else
    {
        RandAddSeedPerfmon();
        CKey secret;
        secret.MakeNewKey(true);
        privKey = CBitcoinSecret(secret).ToString();
    }

    string noMember;
    registerNewGroup(privKey, strDescription, noMember, noMember, GetTime(), -1);

    return getGroupAliasByKey(privKey);
}

Value listgroups(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2 )
        throw runtime_error(
            "listgroups [username] [list_only_ignored=false]\n"
            "get list of group chats\n"
            "if username is given, it will return list of user's groups.");

    string strUsername = (params.size() > 0 ? params[0].get_str() : "");
    bool onlyIgnored = (params.size() > 1 ? params[1].get_bool() : false);

    Array ret;

    if (strUsername.size() && !m_users.count(strUsername))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown user");

    if (onlyIgnored)
    {
        LOCK(cs_twister);
        BOOST_FOREACH(string const &strGroup, m_users[strUsername].m_ignoreGroups)
            ret.push_back(strGroup);
    }
    else
    {
        LOCK(cs_twister);
        map<string,GroupChat>::const_iterator i;
        for (i = m_groups.begin(); i != m_groups.end(); ++i) {
            if (strUsername.size() && !i->second.m_members.count(strUsername))
                continue;
            ret.push_back(i->first);
        }
    }

    return ret;
}

Value getgroupinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getgroupinfo <groupalias>\n"
            "get group description and members");

    string strGroupAlias = params[0].get_str();

    Object ret;

    LOCK(cs_twister);
    if (!m_groups.count(strGroupAlias))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown group alias");

    ret.push_back(Pair("alias",strGroupAlias));
    ret.push_back(Pair("description",m_groups.at(strGroupAlias).m_description));

    Array membersList;
    BOOST_FOREACH( std::string const &n, m_groups.at(strGroupAlias).m_members) {
        membersList.push_back(n);
    }
    ret.push_back(Pair("members",membersList));

    return ret;
}

static void signAndAddDM(const std::string &strFrom, int k, const entry *dm)
{
    entry v;
    if( !createSignedUserpost(v, strFrom, k,
                              USERPOST_FLAG_DM,
                              "", dm, NULL,
                              std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    std::vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strFrom,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strFrom, true);
    if( h.is_valid() ) {
        h.add_piece(k++,buf.data(),buf.size());
    }
}

Value newgroupinvite(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4 )
        throw runtime_error(
            "newgroupinvite <username> <k> <groupalias> '[<newmember>,...]'\n"
            "Invite some new members for a group chat.\n"
            "note: k is increased by at least 2, check getlasthave");

    EnsureWalletIsUnlocked();

    string strFrom        = params[0].get_str();
    int k                 = params[1].get_int();
    string strGroupAlias  = params[2].get_str();
    Array newmembers      = params[3].get_array();

    std::set<std::string> membersList;
    {
        LOCK(cs_twister);
        if (!m_groups.count(strGroupAlias))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown group alias");
        membersList = m_groups.at(strGroupAlias).m_members;
    }

    /* create group_invite DM and send it to each new member */
    for( unsigned int u = 0; u < newmembers.size(); u++ ) {
        string strMember = newmembers[u].get_str();
        membersList.insert(strMember);
        entry groupInvite;
        {
            LOCK(cs_twister);
            groupInvite["desc"] = m_groups.at(strGroupAlias).m_description;
            groupInvite["key"]  = m_groups.at(strGroupAlias).m_privKey;
            if( m_users.count(strMember) )
                m_users[strMember].m_ignoreGroups.erase(strGroupAlias);
        }
        entry payloadMsg;
        payloadMsg["group_invite"] = groupInvite;
        std::vector<char> payloadbuf;
        bencode(std::back_inserter(payloadbuf), payloadMsg);
        std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

        entry dmInvite;
        if( !createDirectMessage(dmInvite, strMember, strMsgData) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "error encrypting to pubkey of destination user");
        signAndAddDM(strFrom, k++, &dmInvite);
    }

    /* create group_members DM and send it to group */
    while( !membersList.empty() ) {
        entry groupMembers;
        int byteCounter = 0;
        while( !membersList.empty() ) {
            std::set<std::string>::iterator it = membersList.begin();
            std::string member=*it;
            groupMembers.list().push_back(member);
            membersList.erase(it);

            // estimate bencoded size. split in multiple DMs.
            byteCounter += member.length() + 2 + member.length()/10;
            if( byteCounter > 150 )
                break;
        }
        entry payloadMsg;
        payloadMsg["group_members"] = groupMembers;
        std::vector<char> payloadbuf;
        bencode(std::back_inserter(payloadbuf), payloadMsg);
        std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

        entry dmMembers;
        if( !createDirectMessage(dmMembers, strGroupAlias, strMsgData) )
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "error encrypting to pubkey of group alias");
        signAndAddDM(strFrom, k++, &dmMembers);
    }

    return Value();
}

Value newgroupdescription(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4 )
        throw runtime_error(
            "newgroupdescription <username> <k> <groupalias> <description>\n"
            "Change group description by sending a new invite DM to group");

    EnsureWalletIsUnlocked();

    string strFrom        = params[0].get_str();
    int k                 = params[1].get_int();
    string strGroupAlias  = params[2].get_str();
    string strDescription = params[3].get_str();

    entry groupInvite;
    {
        LOCK(cs_twister);
        if (!m_groups.count(strGroupAlias))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown group alias");

        m_groups[strGroupAlias].m_description = strDescription;
        groupInvite["desc"] = m_groups.at(strGroupAlias).m_description;
        groupInvite["key"]  = m_groups.at(strGroupAlias).m_privKey;
    }
    entry payloadMsg;
    payloadMsg["group_invite"] = groupInvite;
    std::vector<char> payloadbuf;
    bencode(std::back_inserter(payloadbuf), payloadMsg);
    std::string strMsgData = std::string(payloadbuf.data(),payloadbuf.size());

    entry dmInvite;
    if( !createDirectMessage(dmInvite, strGroupAlias, strMsgData) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "error encrypting to pubkey of group alias");
    signAndAddDM(strFrom, k++, &dmInvite);

    return Value();
}

Value leavegroup(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw runtime_error(
            "leavegroup <username> <groupalias>\n"
            "Stop receiving chats from group");

    string strUser        = params[0].get_str();
    string strGroupAlias  = params[1].get_str();

    LOCK(cs_twister);
    if (!m_groups.count(strGroupAlias))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown group alias");

    if (!m_users.count(strUser))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown user");

    m_users[strUser].m_directmsg.erase(strGroupAlias);
    m_users[strUser].m_ignoreGroups.insert(strGroupAlias);
    m_groups[strGroupAlias].m_members.erase(strUser);

    return Value();
}


Value getpieceavailability(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw runtime_error(
            "getpieceavailability <username> <k>\n"
            "Get piece availability (peer count for this piece)");

    string strUsername    = params[0].get_str();
    int k                 = params[1].get_int();

    torrent_handle h = getTorrentUser(strUsername);
    std::vector<int> avail;
    h.piece_availability(avail);

    return (int)avail.size() > k ? avail.at(k) : 0;
}

Value getpiecemaxseen(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw runtime_error(
            "getpiecemaxseen <username> <k>\n"
            "Get piece max seen availability (max peer count for this piece)");

    string strUsername    = params[0].get_str();
    int k                 = params[1].get_int();

    torrent_handle h = getTorrentUser(strUsername);
    std::vector<int> max_seen;
    h.piece_max_seen(max_seen);

    return (int)max_seen.size() > k ? max_seen.at(k) : 0;
}

Value peekpost(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4 )
        throw runtime_error(
            "peekpost <username> <k> [field='*'] [timeout_sec=90]\n"
            "Peek post from best/faster available source, either\n"
            "local torrent, DHT or remote torrent (peek extension).\n"
            "field is a convenience to return specific post field(s)\n"
            "instead of the whole post (eg. 'url' or 'url,mimetype')");

    boost::shared_ptr<session> ses(m_ses);
    if( !ses )
        throw JSONRPCError(RPC_INTERNAL_ERROR, "uninitialized session");

    string strUsername    = params[0].get_str();
    int k                 = std::max(params[1].get_int(), 0);
    string strField       = "*";
    if( params.size() > 2 )
        strField          = params[2].get_str();
    time_duration timeToWait = seconds(90);
    if( params.size() > 3 )
        timeToWait = seconds(params[3].get_int());

    entry vEntry;

    torrent_handle h = getTorrentUser(strUsername);
    if( h.is_valid() ) {
        std::vector<std::string> pieces;
        int allowed_flags = 0xff;
        int required_flags = 0;
        h.get_pieces(pieces, 1, k, k-1, allowed_flags, required_flags);

        lazy_entry v;
        int pos;
        libtorrent::error_code ec;
        if(pieces.size() &&
           lazy_bdecode(pieces[0].data(), pieces[0].data()+pieces[0].size(), v, ec, &pos) == 0 &&
           v.type() == lazy_entry::dict_t) {
            printf("peekpiece: got piece (%s,%d) from local torrent\n",strUsername.c_str(), k);
            vEntry = v;
        }
    } else {
        /* there is quite some code shared with dhtget, but it is intermigled with
         * torrent's piece peek. so we accept a little copy-paste for now. */
        alert_manager am(10, alert::dht_notification);
        string strResource = "post" + boost::lexical_cast<std::string>(k);
        bool multi = false;
        sha1_hash ih = dhtTargetHash(strUsername,strResource,"s");

        vector<CNode*> dhtProxyNodes;
        if( !DhtProxy::fEnabled ) {
            dhtgetMapAdd(ih, &am);
            dhtGetData(strUsername, strResource, multi, true);
        } else {
            DhtProxy::dhtgetMapAdd(ih, &am);
            dhtProxyNodes = DhtProxy::dhtgetStartRequest(strUsername, strResource, multi);
        }

        h = startTorrentUser(strUsername,true,k);

        // this loop receives alerts from both dht network and torrent peek extension
        while( h.is_valid() && am.wait_for_alert(timeToWait) ) {
            std::unique_ptr<alert> a(am.get());

            dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(&(*a));
            if( rd && rd->m_lst.size() ) {
                entry dhtEntry = rd->m_lst.front();
                entry const *pEntry = dhtEntry.find_key("p");
                if( pEntry && pEntry->type() == entry::dictionary_t ) {
                    entry const *v = pEntry->find_key("v");
                    if( v && v->type() == entry::dictionary_t ) {
                        vEntry = *v;
                    }
                }
                string source = "dht";
                entry const *pSigEntry = dhtEntry.find_key("sig_p");
                if(pSigEntry && pSigEntry->type() == entry::string_t &&
                   pSigEntry->string() == "peek" ) {
                   source = "peek";
                }
                printf("peekpiece: got piece (%s,%d) from %s\n",strUsername.c_str(), k, source.c_str());
                break;
            }
        }

        if( h.is_valid() ) {
            LOCK(cs_twister);
            h.pause();
            h.save_resume_data();
            num_outstanding_resume_data++;
        }

        if( !DhtProxy::fEnabled ) {
            dhtgetMapRemove(ih,&am);
        } else {
            DhtProxy::dhtgetMapRemove(ih,&am);
            DhtProxy::dhtgetStopRequest(dhtProxyNodes, strUsername, strResource, multi);
        }
    }

    Value ret;
    if( vEntry.type() == entry::dictionary_t ) {
        hexcapePost(vEntry);
        if( strField == "*" ) {
            ret = entryToJson(vEntry);
        } else {
            entry const *userpost = vEntry.find_key("userpost");
            if( userpost && userpost->type() == entry::dictionary_t ) {
                if( strField.find(',') == string::npos ) {
                    entry const *f = userpost->find_key(strField);
                    if( f && f->type() == entry::string_t ) {
                        ret = f->string();
                    }
                } else {
                    vector<string> fieldList;
                    Array retList;
                    boost::algorithm::split(fieldList,strField,std::bind1st(std::equal_to<char>(),','),
                                            boost::algorithm::token_compress_on);
                    BOOST_FOREACH(string const& field, fieldList) {
                        entry const *f = userpost->find_key(field);
                        if( f && f->type() == entry::string_t ) {
                            retList.push_back(f->string());
                        } else {
                            retList.push_back("");
                        }
                    }
                    ret = retList;
                }
            }
        }
    } else {
        if(h.is_valid()) {
            throw JSONRPCError(RPC_TIMEOUT, "timeout or post not found");
        } else {
            throw JSONRPCError(RPC_RESOURCE_BUSY_TRY_AGAIN, "resource busy, try again");
        }
    }

    return ret;
}

Value uidtousername(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 )
        throw runtime_error(
            "uidtousername <uid>\n"
            "convert uid to username");

    int uid               = params[0].get_int();

    string strUsername;
    if( !TxNumToUsername(uid, strUsername) )
        throw JSONRPCError(RPC_INTERNAL_ERROR, "TxNumToUsername failed");

    return Value(strUsername);
}

Value usernametouid(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2 )
        throw runtime_error(
            "usernametouid <username> [last=true]\n"
            "convert username to uid");

    string strUsername    = params[0].get_str();
    bool last             = (params.size() > 1) ? params[1].get_bool() : true;

    int uid;
    if( !UsernameToTxNum(strUsername, &uid, last) )
        throw JSONRPCError(RPC_INTERNAL_ERROR, "UsernameToTxNum failed");

    return Value(uid);
}

Value newshorturl(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "newshorturl <username> <k> <url> [mimetype]\n"
            "Shorten URL, create a post containing it add to swarm.\n"
            "Returns the shortened twister URI (multiple options may be returned)");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strUrl      = params[2].get_str();
    string strMimeType;
    if( params.size() > 3 )
        strMimeType    = params[3].get_str();

    Array paramsSub;
    Value res;

    paramsSub.clear();
    paramsSub.push_back(strUsername);
    paramsSub.push_back(k);
    Object fields;
    fields.push_back(Pair("url",strUrl));
    if( strMimeType.size() )
        fields.push_back(Pair("mimetype",strMimeType));
    paramsSub.push_back(fields);
    res = newpostcustom(paramsSub,false);

    paramsSub.clear();
    paramsSub.push_back(strUsername);
    res = usernametouid(paramsSub, false);

    vector<unsigned char> vch;
    vch.resize(8);
    le32enc(&vch[0], res.get_int());
    le32enc(&vch[4], k);

    string uid_k_64 = EncodeBase64(&vch[0], vch.size());

    Array uriOptions;
    uriOptions.push_back(string("twist:")+uid_k_64);

    return uriOptions;
}

Value decodeshorturl(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2 )
        throw runtime_error(
            "decodeshorturl <twist:xxx> [timeout_sec=90]\n"
            "Decodes a shortened URL by twister. May take some time to complete, like dhtget etc.\n"
            "Returns the original [URL,mimetype] or error if not found, timeout");

    string strTwistURI = params[0].get_str();
    int timeout = 0;
    if( params.size() > 1 )
        timeout = params[1].get_int();

    string protocol("twist:");
    if (strTwistURI.find(protocol) != 0) {
        throw JSONRPCError(RPC_PARSE_ERROR, "protocol prefix error");
    }
    string uid_k_64 = strTwistURI.substr(protocol.size());
    if (uid_k_64.length() < 12) {
        throw JSONRPCError(RPC_PARSE_ERROR, "base64 string too small");
    }

    string vch = DecodeBase64(uid_k_64);
    int uid = le32dec(&vch[0]);
    int k = le32dec(&vch[4]);

    Array paramsSub;
    Value res;

    paramsSub.clear();
    paramsSub.push_back(uid);
    res = uidtousername(paramsSub, false);

    string strUsername = res.get_str();

    paramsSub.clear();
    paramsSub.push_back(strUsername);
    paramsSub.push_back(k);
    paramsSub.push_back("url,mimetype");
    if(timeout) {
        paramsSub.push_back(timeout);
    }
    return peekpost(paramsSub,false);
}


