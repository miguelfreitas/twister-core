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
static boost::scoped_ptr<CLevelDB> m_swarmDb;
static int m_threadsToJoin;

static CCriticalSection cs_spamMsg;
static std::string m_preferredSpamLang = "[en]";
static std::string m_receivedSpamMsgStr;
static std::string m_receivedSpamUserStr;
static int64       m_lastSpamTime = 0;
static std::map<std::string,UserData> m_users;

static CCriticalSection cs_seenHashtags;
static std::map<std::string,double> m_seenHashtags;

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

torrent_handle startTorrentUser(std::string const &username, bool following)
{
    bool userInTxDb = usernameExists(username); // keep this outside cs_twister to avoid deadlock
    boost::shared_ptr<session> ses(m_ses);
    if( !userInTxDb || !ses )
        return torrent_handle();

    LOCK(cs_twister);
    if( !m_userTorrent.count(username) ) {
        sha1_hash ih = dhtTargetHash(username, "tracker", "m");

        printf("adding torrent for [%s,tracker]\n", username.c_str());
        add_torrent_params tparams;
        tparams.info_hash = ih;
        tparams.name = username;
        boost::filesystem::path torrentPath = GetDataDir() / "swarm";
        tparams.save_path= torrentPath.string();
        libtorrent::error_code ec;
        create_directory(tparams.save_path, ec);
        std::string filename = combine_path(tparams.save_path, to_hex(ih.to_string()) + ".resume");
        load_file(filename.c_str(), tparams.resume_data);

        m_userTorrent[username] = ses->add_torrent(tparams);
        if( !following ) {
            m_userTorrent[username].auto_managed(true);
        }
        m_userTorrent[username].force_dht_announce();
    }
    if( following ) {
        m_userTorrent[username].set_following(true);
        m_userTorrent[username].auto_managed(false);
        m_userTorrent[username].resume();
    }
    return m_userTorrent[username];
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
    globalDict["lastSpamTime"]      = m_lastSpamTime;
    globalDict["sendSpamMsg"]       = strSpamMessage;
    globalDict["sendSpamUser"]      = strSpamUser;
    globalDict["generate"]          = GetBoolArg("-gen", false);
    int genproclimit = GetArg("-genproclimit", -1);
    if( genproclimit > 0 )
        globalDict["genproclimit"]  = genproclimit;

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
            m_lastSpamTime        = userDict.dict_find_int_value("lastSpamTime");
            string sendSpamMsg    = userDict.dict_find_string_value("sendSpamMsg");
            if( sendSpamMsg.size() ) strSpamMessage = sendSpamMsg;
            string sendSpamUser   = userDict.dict_find_string_value("sendSpamUser");
            if( sendSpamUser.size() ) strSpamUser = sendSpamUser;
            bool generate         = userDict.dict_find_int_value("generate");
            int genproclimit      = userDict.dict_find_int_value("genproclimit");

            if( generate ) {
                Array params;
                params.push_back( generate );
                if( genproclimit > 0 )
                    params.push_back( genproclimit );
                setgenerate(params, false);
            }

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

    libtorrent::error_code ec;

    boost::filesystem::path swarmDbPath = GetDataDir() / "swarm" / "db";
    create_directories(swarmDbPath.string(), ec);
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
            , alert::dht_notification
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
    settings.allow_multiple_connections_per_ip = true;
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
    ses->set_settings(settings);

    printf("libtorrent + dht started\n");

    // wait up to 10 seconds for dht nodes to be set
    for( int i = 0; i < 10; i++ ) {
        MilliSleep(1000);
        session_status ss = ses->status();
        if( ss.dht_nodes )
            break;
    }

    boost::filesystem::path globalDataPath = GetDataDir() / GLOBAL_DATA_FILE;
    loadGlobalData(globalDataPath.string());

    std::set<std::string> torrentsToStart;
    {
        LOCK(cs_twister);
        boost::filesystem::path userDataPath = GetDataDir() / USER_DATA_FILE;
        loadUserData(userDataPath.string(), m_users);
        printf("loaded user_data for %zd users\n", m_users.size());

        // add all user torrents to a std::set (all m_following)
        std::map<std::string,UserData>::const_iterator i;
        for (i = m_users.begin(); i != m_users.end(); ++i) {
            UserData const &data = i->second;
            BOOST_FOREACH(string username, data.m_following) {
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
    return (pindexBest->GetBlockTime() > GetTime() - 2 * 60 * 60);
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
}

int getDhtNodes(boost::int64_t *dht_global_nodes)
{
    boost::shared_ptr<session> ses(m_ses);
    if( !ses )
        return 0;
    session_status ss = ses->status();
    if( dht_global_nodes )
        *dht_global_nodes = ss.dht_global_nodes;
    return ss.dht_nodes;
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
                std::auto_ptr<alert> a(*i);

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
                                            dhtGetData(n->string(), r->string(), t->string() == "m");
                                        } else if( neighborCheck[ih] ) {
                                            sha1_hash ihStatus = dhtTargetHash(n->string(), "status", "s");

                                            if( !statusCheck.count(ihStatus) ||
                                                statusCheck[ihStatus] + 3600 < GetTime() ) {
#if DEBUG_NEIGHBOR_TORRENT
                                                printf("known neighbor. starting a new dhtget check of [%s,%s,%s]\n",
                                                        n->string().c_str(), "status", "s");
#endif
                                                statusCheck[ihStatus] = GetTime();
                                                dhtGetData(n->string(), "status", false);
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
                            dhtGetData(dd->m_username, "status", false);
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
                    num_outstanding_resume_data--;
                    if (!rda->resume_data) continue;

                    torrent_handle h = rda->handle;
                    torrent_status st = h.status(torrent_handle::query_save_path);
                    std::vector<char> out;
                    bencode(std::back_inserter(out), *rda->resume_data);
                    save_file(combine_path(st.save_path, to_hex(st.info_hash.to_string()) + ".resume"), out);
                }

                if (alert_cast<save_resume_data_failed_alert>(*i))
                {
                    --num_outstanding_resume_data;
                }
        }
    }
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

bool processReceivedDM(lazy_entry const* post)
{
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
                printf("acceptSignedPost: private key not available trying to decrypt DM.\n");
            } else {
                std::string textOut;
                if( key.Decrypt(sec, textOut) ) {
                    /* this printf is good for debug, but bad for security.
                    printf("Received DM for user '%s' text = '%s'\n",
                           item.second.username.c_str(),
                           textOut.c_str());
                    */

                    std::string n = post->dict_find_string_value("n");

                    StoredDirectMsg stoDM;
                    stoDM.m_fromMe  = false;
                    stoDM.m_text    = textOut;
                    stoDM.m_utcTime = post->dict_find_int_value("time");;

                    LOCK(cs_twister);
                    // store this dm in memory list, but prevent duplicates
                    std::vector<StoredDirectMsg> &dmsFromToUser = m_users[item.second.username].m_directmsg[n];
                    std::vector<StoredDirectMsg>::iterator it;
                    for( it = dmsFromToUser.begin(); it != dmsFromToUser.end(); ++it ) {
                        if( stoDM.m_utcTime == (*it).m_utcTime &&
                            stoDM.m_text    == (*it).m_text ) {
                            break;
                        }
                        if( stoDM.m_utcTime < (*it).m_utcTime && !(*it).m_fromMe) {
                            dmsFromToUser.insert(it, stoDM);
                            break;
                        }
                    }
                    if( it == dmsFromToUser.end() ) {
                        dmsFromToUser.push_back(stoDM);
                    }

                    return true;
                }
            }
        }
    }
    return false;
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

                        lazy_entry const* dm = post->dict_find_dict("dm");
                        if( dm && flags ) {
                            (*flags) |= USERPOST_FLAG_DM;
                            processReceivedDM(post);
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
                          std::string const &msg,               // either msg.size() or
                          entry const *rt, entry const *sig_rt, // rt != NULL or
                          entry const *dm,                      // dm != NULL.
                          std::string const &reply_n, int reply_k
                          )
{
    entry &userpost = v["userpost"];

    //
    userpost["n"] = username;
    userpost["k"] = k;
    userpost["time"] = GetAdjustedTime();
    userpost["height"] = getBestHeight() - 1; // be conservative

    if( msg.size() ) {
        //userpost["t"] = "post";
        userpost["msg"] = msg;
    } else if ( rt != NULL && sig_rt != NULL ) {
        //userpost["t"] = "rt";
        userpost["rt"] = *rt;
        userpost["sig_rt"] = *sig_rt;
    } else if ( dm != NULL ) {
        //userpost["t"] = "dm";
        userpost["dm"] = *dm;
    } else {
        printf("createSignedUserpost: unknown type\n");
        return false;
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
    if( !getUserPubKey(to, pubkey) ) {
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
    bool hasPreferredLang  = m_preferredSpamLang.length();
    bool isSameLang        = hasPreferredLang && hasSingleLangCode &&
                             message.find(m_preferredSpamLang) != string::npos;
    bool currentlyEmpty    = !m_receivedSpamMsgStr.length();

    if( currentlyEmpty || (isSameLang && rand() < (RAND_MAX/2)) ) {
        m_receivedSpamMsgStr = message;
        m_receivedSpamUserStr = user;
    }
}

void updateSeenHashtags(std::string &message, int64_t msgTime)
{
    if( message.find('#') == string::npos )
        return;

    boost::int64_t curTime = GetAdjustedTime();
    if( msgTime > curTime ) msgTime = curTime;
    
    double vote = 1.0;
    if( msgTime + (2*3600) < curTime ) {
        double timeDiff = (curTime - msgTime);
        timeDiff /= (2*3600);
        vote /= timeDiff;
    }

    // split and look for hashtags
    vector<string> tokens;
    set<string> hashtags;
    boost::algorithm::split(tokens,message,boost::algorithm::is_any_of(" \n\t.,:/?!;'\"()[]{}*"),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 ) {
            string word = token.substr(1);
#ifdef HAVE_BOOST_LOCALE
            word = boost::locale::to_lower(word);
#else
            boost::algorithm::to_lower(word);
#endif
            if( token.at(0) == '#') {
                hashtags.insert(word);
            }
        }
    }
    
    if( hashtags.size() ) {
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
    
    unsigned char vchSig[65];
    RAND_bytes(vchSig,sizeof(vchSig));
    v["sig_userpost"] = HexStr( string((const char *)vchSig, sizeof(vchSig)) );
    return v;
}


void dhtGetData(std::string const &username, std::string const &resource, bool multi)
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
    ses->dht_getData(username,resource,multi);
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
        dhtGetData(strUsername, strResource, multi);
    } else {
        DhtProxy::dhtgetMapAdd(ih, &am);
        dhtProxyNodes = DhtProxy::dhtgetStartRequest(strUsername, strResource, multi);
    }

    Array ret;
    std::set<std::string> uniqueSigPs;

    int repliesReceived = 0;
    while( am.wait_for_alert(timeToWait) ) {
        std::auto_ptr<alert> a(am.get());

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
        h.get_pieces(pieces, 1, max_id, since_id, USERPOST_FLAG_RT);

        if( pieces.size() ) {
            string const& piece = pieces.front();
            lazy_entry v;
            int pos;
            libtorrent::error_code ec;
            if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0) {
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

    if( !createSignedUserpost(v, strUsername, k, strMsg,
                         NULL, NULL, NULL,
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

    // split and look for mentions and hashtags
    vector<string> tokens;
    boost::algorithm::split(tokens,strMsg,boost::algorithm::is_any_of(" \n\t.,:/?!;'\"()[]{}*"),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 ) {
            string word = token.substr(1);
#ifdef HAVE_BOOST_LOCALE
            word = boost::locale::to_lower(word);
#else
            boost::algorithm::to_lower(word);
#endif
            if( token.at(0) == '#') {
                dhtPutData(word, "hashtag", true,
                                 v, strUsername, GetAdjustedTime(), 0);
            } else if( token.at(0) == '@') {
                dhtPutData(word, "mention", true,
                                 v, strUsername, GetAdjustedTime(), 0);
            }
        }
    }

    hexcapePost(v);
    return entryToJson(v);
}

Value newdirectmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "newdirectmsg <from> <k> <to> <msg>\n"
            "Post a new dm to swarm");

    EnsureWalletIsUnlocked();

    string strFrom     = params[0].get_str();
    int k              = params[1].get_int();
    string strTo       = params[2].get_str();
    string strMsg      = params[3].get_str();

    entry dm;
    if( !createDirectMessage(dm, strTo, strMsg) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "error encrypting to pubkey of destination user");

    entry v;
    if( !createSignedUserpost(v, strFrom, k, "",
                              NULL, NULL, &dm,
                              std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    std::vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strFrom,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    {
        StoredDirectMsg stoDM;
        stoDM.m_fromMe  = true;
        stoDM.m_text    = strMsg;
        stoDM.m_utcTime = v["userpost"]["time"].integer();

        LOCK(cs_twister);
        m_users[strFrom].m_directmsg[strTo].push_back(stoDM);
    }

    torrent_handle h = startTorrentUser(strFrom, true);
    h.add_piece(k,buf.data(),buf.size());

    hexcapePost(v);
    return entryToJson(v);
}

Value newrtmsg(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 3))
        throw runtime_error(
            "newrtmsg <username> <k> <rt_v_object>\n"
            "Post a new RT to swarm");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    int k              = params[1].get_int();
    string strK        = boost::lexical_cast<std::string>(k);
    entry  vrt         = jsonToEntry(params[2].get_obj());
    unHexcapePost(vrt);
    entry const *rt    = vrt.find_key("userpost");
    entry const *sig_rt= vrt.find_key("sig_userpost");

    entry v;
    // [MF] Warning: findLastPublicPostLocalUser requires that we follow ourselves
    int lastk = findLastPublicPostLocalUser(strUsername);
    if( lastk >= 0 )
        v["userpost"]["lastk"] = lastk;

    if( !createSignedUserpost(v, strUsername, k, "",
                              rt, sig_rt, NULL,
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

    hexcapePost(v);
    return entryToJson(v);
}

Value getposts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "getposts <count> '[{\"username\":username,\"max_id\":max_id,\"since_id\":since_id},...]' [flags]\n"
            "get posts from users\n"
            "max_id and since_id may be omited");

    int count          = params[0].get_int();
    Array users        = params[1].get_array();
    int flags          = (params.size() > 2) ? params[2].get_int() : USERPOST_FLAG_RT;

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
            h.get_pieces(pieces, count, max_id, since_id, flags);

            BOOST_FOREACH(string const& piece, pieces) {
                lazy_entry v;
                int pos;
                libtorrent::error_code ec;
                if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0) {
                    lazy_entry const* post = v.dict_find_dict("userpost");
                    int64 time = post->dict_find_int_value("time",-1);

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

            entry v = formatSpamPost(m_receivedSpamMsgStr, m_receivedSpamUserStr);
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
                userMsgs.push_back(dmObj);
            }
            if( userMsgs.size() ) {
                ret.push_back(Pair(remoteUsername,userMsgs));
            }
        }
    }

    return ret;
}


Value setspammsg(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "setspammsg <username> <msg>\n"
            "Set spam message attached to generated blocks");

    string strUsername = params[0].get_str();
    string strMsg      = params[1].get_str();

    int spamMsgUtf8Size = utf8::num_characters(strMsg.begin(), strMsg.end());
    if (spamMsgUtf8Size < 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "spam message invalid utf8");
    if (spamMsgUtf8Size == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "empty spam message");
    if (spamMsgUtf8Size > MAX_SPAM_MSG_SIZE)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "spam message too big");

    strSpamUser    = strUsername;
    strSpamMessage = strMsg;

    return Value();
}

Value getspammsg(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "getspammsg\n"
            "get spam message attached to generated blocks");

    Array ret;
    ret.push_back(strSpamUser);
    ret.push_back(strSpamMessage);

    return ret;
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
    if (fHelp || (params.size() != 1))
        throw runtime_error(
            "getlasthave <username>\n"
            "get last 'have' (higher post number) of each user user we follow");

    string localUser = params[0].get_str();

    std::set<std::string> following;
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
