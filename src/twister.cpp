#include "twister.h"

#include "twister_utils.h"

#include "main.h"
#include "init.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

#include <boost/filesystem.hpp>
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

using namespace libtorrent;
static session *ses = NULL;
static int num_outstanding_resume_data;

static CCriticalSection cs_dhtgetMap;
static map<sha1_hash, alert_manager*> m_dhtgetMap;

static CCriticalSection cs_twister;
static map<std::string, bool> m_specialResources;
static map<std::string, torrent_handle> m_userTorrent;

static std::string m_preferredSpamLang = "[en]";
static std::string m_receivedSpamMsgStr;
static std::string m_receivedSpamUserStr;
static std::map<std::string,UserData> m_users;

sha1_hash dhtTargetHash(std::string const &username, std::string const &resource, std::string const &type)
{
    entry target;
    target["n"] = username;
    target["r"] = resource;
    target["t"] = type;

    std::vector<char> buf;
    bencode(std::back_inserter(buf), target);
    return hasher(buf.data(), buf.size()).final();
}

torrent_handle startTorrentUser(std::string const &username)
{
    LOCK(cs_twister);
    if( !m_userTorrent.count(username) ) {
        sha1_hash ih = dhtTargetHash(username, "tracker", "m");

        printf("adding torrent for [%s,tracker]\n", username.c_str());
        add_torrent_params tparams;
        tparams.info_hash = ih;
        tparams.name = username;
        boost::filesystem::path torrentPath = GetDataDir() / "swarm";
        tparams.save_path= torrentPath.string();

        error_code ec;
        create_directory(tparams.save_path, ec);

        std::string filename = combine_path(tparams.save_path, to_hex(ih.to_string()) + ".resume");
        load_file(filename.c_str(), tparams.resume_data);

        m_userTorrent[username] = ses->add_torrent(tparams);
        m_userTorrent[username].force_dht_announce();
        torrent_status status = m_userTorrent[username].status();
    }
    return m_userTorrent[username];
}

int lastPostKfromTorrent(std::string const &username)
{
    if( !m_userTorrent.count(username) )
        return -1;

    torrent_status status = m_userTorrent[username].status();
    return status.last_have;
}

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

    ses = new session(fingerprint("TW", LIBTORRENT_VERSION_MAJOR, LIBTORRENT_VERSION_MINOR, 0, 0)
            , session::add_default_plugins
            , alert::dht_notification
            , ipStr.size() ? ipStr.c_str() : NULL
            , std::make_pair(listen_port, listen_port));

    std::vector<char> in;
    boost::filesystem::path sesStatePath = GetDataDir() / "ses_state";
    if (load_file(sesStatePath.string(), in) == 0)
    {
            lazy_entry e;
            if (lazy_bdecode(&in[0], &in[0] + in.size(), e, ec) == 0)
                    ses->load_state(e);
    }

    ses->start_upnp();
    ses->start_natpmp();

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
    dhts.restrict_routing_ips = false;
    dhts.restrict_search_ips = false;
    ses->set_dht_settings(dhts);
    ses->start_dht();

    session_settings settings;
    // settings to test local connections
    settings.allow_multiple_connections_per_ip = true;
    settings.enable_outgoing_utp = false; // test (netstat display)
    //settings.dht_announce_interval = 60; // test
    //settings.min_announce_interval = 60; // test
    ses->set_settings(settings);


    boost::filesystem::path userDataPath = GetDataDir() / "user_data";
    loadUserData(userDataPath.string(), m_users);
    printf("loaded user_data for %zd users\n", m_users.size());

    // now restart the user torrents (all m_following)
    std::map<std::string,UserData>::const_iterator i;
    for (i = m_users.begin(); i != m_users.end(); ++i) {
        UserData const &data = i->second;
        BOOST_FOREACH(string username, data.m_following) {
            startTorrentUser(username);
        }
    }

    printf("libtorrent + dht started\n");
}

void ThreadMaintainDHTNodes()
{
    RenameThread("maintain-dht-nodes");

    while(1) {
        MilliSleep(15000);

        if( ses ) {
            vector<CAddress> vAddr = addrman.GetAddr();
            session_status ss = ses->status();
            if( ss.dht_nodes < (int)(vNodes.size() + vAddr.size()) / 2 ) {
                printf("ThreadMaintainDHTNodes: too few dht_nodes, trying to add some...\n");
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes) {

                    // if !fInbound we created this connection so ip is reachable
                    if( !pnode->fInbound ) {
                        std::string addr = pnode->addr.ToStringIP();
                        int port = pnode->addr.GetPort() + LIBTORRENT_PORT_OFFSET;

                        printf("Adding dht node (outbound) %s:%d\n", addr.c_str(), port);
                        ses->add_dht_node(std::pair<std::string, int>(addr, port));
                    }
                }
                BOOST_FOREACH(const CAddress &a, vAddr) {
                    std::string addr = a.ToStringIP();
                    int port = a.GetPort() + LIBTORRENT_PORT_OFFSET;
                    printf("Adding dht node (addrman) %s:%d\n", addr.c_str(), port);
                    ses->add_dht_node(std::pair<std::string, int>(addr, port));
                }
            }
        }
    }
}

void ThreadSessionAlerts()
{
    static map<sha1_hash, entry> neighborCheck;

    while(!ses) {
        MilliSleep(200);
    }
    while (ses) {
        alert const* a = ses->wait_for_alert(seconds(10));
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

                                    LOCK(cs_dhtgetMap);
                                    std::map<sha1_hash, alert_manager*>::iterator mi = m_dhtgetMap.find(ih);
                                    if( mi != m_dhtgetMap.end() ) {
                                        alert_manager *am = (*mi).second;
                                        am->post_alert(*rd);
                                    } else {
                                        printf("ThreadSessionAlerts: received dht [%s,%s,%s] but no alert_manager registered\n",
                                               n->string().c_str(), r->string().c_str(), t->string().c_str() );
                                    }
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
                                uint256 userhash = SerializeHash(n->string());
                                if( !GetTransaction(userhash, txOut, hashBlock) ) {
                                    printf("Special Resource but username is unknown - ignoring\n");
                                } else {
                                        // now we do our own search to make sure we are really close to this target
                                    sha1_hash ih = dhtTargetHash(n->string(), r->string(), t->string());

                                    if( !neighborCheck.count(ih) ) {
                                        printf("possiblyNeighbor of [%s,%s,%s] - starting a new dhtget to be sure\n",
                                               n->string().c_str(),
                                               r->string().c_str(),
                                               t->string().c_str());

                                        neighborCheck[ih] = gd->m_target;
                                        ses->dht_getData(n->string(), r->string(), t->string() == "m");
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
                    printf("get_data_done [%s,%s,%s] is_neighbor=%d got_data=%d\n",
                           dd->m_username.c_str(), dd->m_resource.c_str(), dd->m_multi ? "m" : "s",
                           dd->m_is_neighbor, dd->m_got_data);

                    sha1_hash ih = dhtTargetHash(dd->m_username, dd->m_resource, dd->m_multi ? "m" : "s");

                    {
                        LOCK(cs_dhtgetMap);
                        std::map<sha1_hash, alert_manager*>::iterator mi = m_dhtgetMap.find(ih);
                        if( mi != m_dhtgetMap.end() && !dd->m_got_data ) {
                            // post alert to return from wait_for_alert in dhtget()
                            alert_manager *am = (*mi).second;
                            am->post_alert(*dd);
                        }
                    }

                    if( dd->m_is_neighbor && m_specialResources.count(dd->m_resource) &&
                        neighborCheck.count(ih) ) {
                        // Do something!
                        printf("Neighbor of special resource - do something!\n");
                        if( dd->m_resource == "tracker" ) {
                            startTorrentUser(dd->m_username);
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

void encryptDecryptTest()
{
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    string textIn("Encrypted with public key, decrypted with private key");
    ecies_secure_t sec;

    bool encrypted = key1.GetPubKey().Encrypt(textIn, sec);
    printf("encrypted = %d [key %zd, mac %zd, orig %zd, body %zd]\n", encrypted,
           sec.key.size(), sec.mac.size(), sec.orig, sec.body.size());

    std::string textOut;
    bool decrypt1 = key1.Decrypt(sec, textOut);
    printf("decrypt1 = %d\n", decrypt1);
    if( decrypt1 ) {
        printf("textOut = '%s'\n", textOut.c_str());
    }

    bool decrypt2 = key2.Decrypt(sec, textOut);
    printf("decrypt2 = %d\n", decrypt2);
}

void startSessionTorrent(boost::thread_group& threadGroup)
{
    printf("startSessionTorrent (waiting for external IP)\n");

    m_specialResources["tracker"] = true;
    m_specialResources["swarm"] = true;


    threadGroup.create_thread(boost::bind(&ThreadWaitExtIP));
    threadGroup.create_thread(boost::bind(&ThreadMaintainDHTNodes));
    threadGroup.create_thread(boost::bind(&ThreadSessionAlerts));

    encryptDecryptTest();
}

bool yes(libtorrent::torrent_status const&)
{ return true; }

void stopSessionTorrent()
{
    if( ses ){
            ses->pause();

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
                printf("\r%d  ", num_outstanding_resume_data);
            }
            printf("\nwaiting for resume data [%d]\n", num_outstanding_resume_data);
            while (num_outstanding_resume_data > 0)
            {
                MilliSleep(100);
            }

            printf("\nsaving session state\n");

            entry session_state;
            ses->save_state(session_state);

	    std::vector<char> out;
	    bencode(std::back_inserter(out), session_state);
	    boost::filesystem::path sesStatePath = GetDataDir() / "ses_state";
	    save_file(sesStatePath.string(), out);

	    delete ses;
	    ses = NULL;
    }

    if( m_users.size() ) {
        printf("saving user_data (followers and DMs)...\n");
        boost::filesystem::path userDataPath = GetDataDir() / "user_data";
        saveUserData(userDataPath.string(), m_users);
    }

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


bool getUserPubKey(std::string const &strUsername, CPubKey &pubkey)
{
    {
      CKeyID keyID;
      if( pwalletMain->GetKeyIdFromUsername(strUsername, keyID) ) {
        if( !pwalletMain->GetPubKey(keyID, pubkey) ) {
            // error? should not have failed.
        }
      }
    }

    if( !pubkey.IsValid() ) {
      CTransaction txOut;
      uint256 hashBlock;
      uint256 userhash = SerializeHash(strUsername);
      if( !GetTransaction(userhash, txOut, hashBlock) ) {
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
    }
    return true;
}


bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign)
{
    CPubKey pubkey;
    if( !getUserPubKey(strUsername, pubkey) ) {
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
                    printf("Received DM for user '%s' text = '%s'\n",
                           item.second.username.c_str(),
                           textOut.c_str());

                    std::string n = post->dict_find_string_value("n");

                    StoredDirectMsg stoDM;
                    stoDM.m_fromMe  = false;
                    stoDM.m_text    = textOut;
                    stoDM.m_utcTime = post->dict_find_int_value("time");;

                    LOCK(cs_twister);
                    m_users[item.second.username].m_directmsg[n].push_back(stoDM);

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
    error_code ec;
    if (lazy_bdecode(data, data + data_size, v, ec, &pos) == 0) {

        if( v.type() == lazy_entry::dict_t ) {
            lazy_entry const* post = v.dict_find_dict("userpost");
            std::string sig = v.dict_find_string_value("sig_userpost");

            if( !post || !sig.size() ) {
                sprintf(errbuf,"missing post or signature.");
            } else {
                std::string n = post->dict_find_string_value("n");
                std::string msg = post->dict_find_string_value("msg");
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
                } else if( height < 0 || (height > getBestHeight() && getBestHeight()) ) {
                    sprintf(errbuf,"post from future not accepted (height: %d > %d)",
                            height, getBestHeight());
                } else if( msg.size() && msg.size() > 140 ) {
                    sprintf(errbuf,"msg too big (%zd > 140)", msg.size());
                } else {
                    std::pair<char const*, int> postbuf = post->data_section();
                    ret = verifySignature(
                            std::string(postbuf.first,postbuf.second),
                            username, sig);
                    if( !ret ) {
                        sprintf(errbuf,"bad post signature");
                    } else {
                        lazy_entry const* rt = post->dict_find_dict("rt");
                        std::string sig_rt = post->dict_find_string_value("sig_rt");

                        if( rt ) {
                            if( flags ) (*flags) |= USERPOST_FLAG_RT;
                            std::string username_rt = rt->dict_find_string_value("n");

                            std::pair<char const*, int> rtbuf = rt->data_section();
                            ret = verifySignature(
                                    std::string(rtbuf.first,rtbuf.second),
                                    username_rt, sig_rt);
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
    uint256 userhash = SerializeHash(username);
    if( !GetTransaction(userhash, txOut, hashBlock) ) {
        printf("validatePostNumberForUser: username is unknown\n");
        return false;
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];

    if( k < 0 )
        return false;
    if( getBestHeight() && k > 2*(getBestHeight() - pblockindex->nHeight) + 20)
        return false;

    return true;
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

void receivedSpamMessage(std::string const &message, std::string const &user)
{
    LOCK(cs_twister);
    if( !m_receivedSpamMsgStr.length() ||
         (m_preferredSpamLang.length() && message.find(m_preferredSpamLang) != string::npos) ) {
        m_receivedSpamMsgStr = message;
        m_receivedSpamUserStr = user;
    }
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

    ses->dht_putData(strUsername, strResource, multi, value, strSigUser, timeutc, seq);

    return Value();
}

Value dhtget(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "dhtget <username> <resource> <s(ingle)/m(ulti)>\n"
            "Get resource from dht network");

    string strUsername = params[0].get_str();
    string strResource = params[1].get_str();
    string strMulti    = params[2].get_str();

    bool multi = (strMulti == "m");

    alert_manager am(10, alert::dht_notification);
    sha1_hash ih = dhtTargetHash(strUsername,strResource,strMulti);

    {
        LOCK(cs_dhtgetMap);
        m_dhtgetMap[ih] = &am;
    }

    ses->dht_getData(strUsername, strResource, multi);

    Value ret = Array();

    if( am.wait_for_alert(seconds(20)) ) {
        std::auto_ptr<alert> a(am.get());

        dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(&(*a));
        if( rd ) {
            ret = entryToJson(rd->m_lst);
        } else {
            // cast failed => dht_reply_data_done_alert => no data
        }
    }

    {
        LOCK(cs_dhtgetMap);
        m_dhtgetMap.erase(ih);
    }

    return ret;
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
    if( !createSignedUserpost(v, strUsername, k, strMsg,
                         NULL, NULL, NULL,
                         strReplyN, replyK) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        ses->dht_putData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), 1);
    }

    // post to dht as well
    ses->dht_putData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), 1);

    // is this a reply? notify
    if( strReplyN.length() ) {
        ses->dht_putData(strReplyN, string("replies")+strReplyK, true,
                         v, strUsername, GetAdjustedTime(), 0);
    }

    // split and look for mentions and hashtags
    vector<string> tokens;
    boost::algorithm::split(tokens,strMsg,boost::algorithm::is_any_of(" \n\t"),
                            boost::algorithm::token_compress_on);
    BOOST_FOREACH(string const& token, tokens) {
        if( token.length() >= 2 ) {
            string word = token.substr(1);
            if( token.at(0) == '#') {
                ses->dht_putData(word, "hashtag", true,
                                 v, strUsername, GetAdjustedTime(), 0);
            } else if( token.at(0) == '@') {
                ses->dht_putData(word, "mention", true,
                                 v, strUsername, GetAdjustedTime(), 0);
            }
        }
    }

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

    torrent_handle h = startTorrentUser(strFrom);
    h.add_piece(k,buf.data(),buf.size());

    StoredDirectMsg stoDM;
    stoDM.m_fromMe  = true;
    stoDM.m_text    = strMsg;
    stoDM.m_utcTime = v["userpost"]["time"].integer();
    {
        LOCK(cs_twister);

        std::list<StoredDirectMsg> &dmsFromToUser = m_users[strFrom].m_directmsg[strTo];
        std::list<StoredDirectMsg>::const_iterator it;
        // prevent duplicates
        for( it = dmsFromToUser.begin(); it != dmsFromToUser.end(); ++it ) {
            if( stoDM.m_utcTime == (*it).m_utcTime &&
                stoDM.m_text    == (*it).m_text ) {
                break;
            }
        }
        if( it != dmsFromToUser.end() ) {
            dmsFromToUser.push_back(stoDM);
        }
    }

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
    entry const *rt    = vrt.find_key("userpost");
    entry const *sig_rt= vrt.find_key("sig_userpost");

    entry v;
    if( !createSignedUserpost(v, strUsername, k, "",
                              rt, sig_rt, NULL,
                              std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg,NULL) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        ses->dht_putData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), 1);
    }

    // post to dht as well
    ses->dht_putData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), 1);

    // notification to keep track of RTs of the original post
    if( rt ) {
        string rt_user = rt->find_key("n")->string();
        string rt_k    = boost::lexical_cast<std::string>(rt->find_key("k")->integer());
        ses->dht_putData(rt_user, string("rts")+rt_k, true,
                         v, strUsername, GetAdjustedTime(), 0);
    }

    return entryToJson(v);
}

Value getposts(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "getposts <count> [{\"username\":username,\"max_id\":max_id,\"since_id\":since_id},...]\n"
            "get posts from users\n"
            "max_id and since_id may be omited or -1");

    int count          = params[0].get_int();
    Array users        = params[1].get_array();

    std::multimap<int64,entry> postsByTime;

    for( unsigned int u = 0; u < users.size(); u++ ) {
        Object user = users[u].get_obj();
        string strUsername;
        int max_id = -1;
        int since_id = -1;

        for (Object::const_iterator i = user.begin(); i != user.end(); ++i) {
            if( i->name_ == "username" ) strUsername = i->value_.get_str();
            if( i->name_ == "max_id" ) max_id = i->value_.get_int();
            if( i->name_ == "since_id" ) since_id = i->value_.get_int();
        }

        if( strUsername.size() && m_userTorrent.count(strUsername) &&
            m_userTorrent[strUsername].is_valid() ){

            std::vector<std::string> pieces;
            m_userTorrent[strUsername].get_pieces(pieces, count, max_id, since_id, USERPOST_FLAG_RT);

            BOOST_FOREACH(string const& piece, pieces) {
                lazy_entry v;
                int pos;
                error_code ec;
                if (lazy_bdecode(piece.data(), piece.data()+piece.size(), v, ec, &pos) == 0) {
                    lazy_entry const* post = v.dict_find_dict("userpost");
                    int64 time = post->dict_find_int_value("time",-1);

                    entry vEntry;
                    vEntry = v;
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
        LOCK(cs_twister);
        if( m_receivedSpamMsgStr.length() ) {
            // we must agree on an acceptable level here
            if( rand() < (RAND_MAX/10) ) {
                entry v;
                entry &userpost = v["userpost"];

                userpost["n"] = m_receivedSpamUserStr;
                userpost["k"] = 1;
                userpost["time"] = GetAdjustedTime();
                userpost["height"] = getBestHeight();

                userpost["msg"] = m_receivedSpamMsgStr;

                unsigned char vchSig[65];
                RAND_bytes(vchSig,sizeof(vchSig));
                v["sig_userpost"] = std::string((const char *)vchSig, sizeof(vchSig));
                ret.insert(ret.begin(),entryToJson(v));
            }
            m_receivedSpamMsgStr = "";
            m_receivedSpamUserStr = "";
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

    LOCK(cs_twister);
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
    LOCK(cs_twister);
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

    LOCK(cs_twister);
    for( unsigned int u = 0; u < users.size(); u++ ) {
        string username = users[u].get_str();

        if( !m_users[localUser].m_following.count(username) ) {
            if( m_userTorrent.count(username) ) {
                // perhaps torrent is already initialized due to neighborhood
                m_users[localUser].m_following.insert(username);
            } else {
                torrent_handle h = startTorrentUser(username);
                if( h.is_valid() ) {
                    m_users[localUser].m_following.insert(username);
                }
            }
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

        if( m_users[localUser].m_following.count(username) ) {
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
    BOOST_FOREACH(string username, m_users[localUser].m_following) {
        ret.push_back(username);
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

    Object ret;
    LOCK(cs_twister);
    BOOST_FOREACH(string username, m_users[localUser].m_following) {
        ret.push_back(Pair(username,lastPostKfromTorrent(username)));
    }

    return ret;
}

Value listusernamespartial(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "listusernamespartial <username_starts_with> <count>\n"
            "get list of usernames starting with");

    string userStartsWith = params[0].get_str();
    size_t count          = params[1].get_int();

    set<string> retStrings;

    // priorize users in following list
    {
        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CKeyID, CKeyMetadata)& item, pwalletMain->mapKeyMetadata) {
            LOCK(cs_twister);
            BOOST_FOREACH(const string &user, m_users[item.second.username].m_following) {
                int toCompare = std::min( userStartsWith.size(), user.size() );
                if( memcmp( user.data(), userStartsWith.data(), toCompare ) == 0 )
                    retStrings.insert( user );
                if( retStrings.size() >= count )
                    break;
            }
        }
    }

    // now the rest, the entire block chain
    for(CBlockIndex* pindex = pindexBest; pindex && retStrings.size() < count; pindex = pindex->pprev ) {
        CBlock block;
        if( !ReadBlockFromDisk(block, pindex) )
            continue;

        BOOST_FOREACH(const CTransaction&tx, block.vtx) {
            if( !tx.IsSpamMessage() ) {
                string txUsername = tx.userName.ExtractSmallString();
                int toCompare = std::min( userStartsWith.size(), txUsername.size() );
                if( memcmp( txUsername.data(), userStartsWith.data(), toCompare ) == 0 )
                    retStrings.insert( txUsername );
                if( retStrings.size() >= count )
                   break;
            }
        }
    }

    Array ret;
    BOOST_FOREACH(string username, retStrings) {
        ret.push_back(username);
    }

    return ret;
}

