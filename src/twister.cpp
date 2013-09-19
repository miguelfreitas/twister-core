#include "twister.h"

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
static map<std::string, bool> m_specialResources;
static map<std::string, torrent_handle> m_userTorrent;

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

int load_file(std::string const& filename, std::vector<char>& v, libtorrent::error_code& ec, int limit = 8000000)
{
	ec.clear();
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL)
	{
		ec.assign(errno, boost::system::get_generic_category());
		return -1;
	}

	int r = fseek(f, 0, SEEK_END);
	if (r != 0)
	{
		ec.assign(errno, boost::system::get_generic_category());
		fclose(f);
		return -1;
	}
	long s = ftell(f);
	if (s < 0)
	{
		ec.assign(errno, boost::system::get_generic_category());
		fclose(f);
		return -1;
	}

	if (s > limit)
	{
		fclose(f);
		return -2;
	}

	r = fseek(f, 0, SEEK_SET);
	if (r != 0)
	{
		ec.assign(errno, boost::system::get_generic_category());
		fclose(f);
		return -1;
	}

	v.resize(s);
	if (s == 0)
	{
		fclose(f);
		return 0;
	}

	r = fread(&v[0], 1, v.size(), f);
	if (r < 0)
	{
		ec.assign(errno, boost::system::get_generic_category());
		fclose(f);
		return -1;
	}

	fclose(f);

	if (r != s) return -3;

	return 0;
}

int save_file(std::string const& filename, std::vector<char>& v)
{
	using namespace libtorrent;

	// TODO: don't use internal file type here. use fopen()
	file f;
	error_code ec;
	if (!f.open(filename, file::write_only, ec)) return -1;
	if (ec) return -1;
	file::iovec_t b = {&v[0], v.size()};
	size_type written = f.writev(0, &b, 1, ec);
	if (written != int(v.size())) return -3;
	if (ec) return -3;
	return 0;
}

torrent_handle startTorrentUser(std::string const &username)
{
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
        load_file(filename.c_str(), tparams.resume_data, ec);

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
    if (load_file(sesStatePath.string(), in, ec) == 0)
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
    printf("libtorrent + dht stopped\n");
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

    CKey key;
    if (!pwalletMain->GetKey(keyID, key)) {
        printf("createSignature: private key not available for user '%s'.\n", strUsername.c_str());
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

bool acceptSignedPost(char const *data, int data_size, std::string username, int seq, std::string &errmsg)
{
    bool ret = false;
    char errbuf[200]="";

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
                } else if( height < 0 || height > getBestHeight() ) {
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
                            std::string username_rt = rt->dict_find_string_value("n");

                            std::pair<char const*, int> rtbuf = rt->data_section();
                            ret = verifySignature(
                                    std::string(rtbuf.first,rtbuf.second),
                                    username_rt, sig_rt);
                            if( !ret ) {
                                sprintf(errbuf,"bad RT signature");
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
    uint256 userhash = SerializeHash(username);
    if( !GetTransaction(userhash, txOut, hashBlock) ) {
        printf("validatePostNumberForUser: username is unknown\n");
        return false;
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];

    if( k < 0 || k > 2*(getBestHeight() - pblockindex->nHeight) + 10)
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

Value entryToJson(const entry &e)
{
    Array lst;
    Object o;
    switch( e.type() ) {
        case entry::int_t:
            return e.integer();
        case entry::string_t:
            return e.string();
        case entry::list_t:
            for (entry::list_type::const_iterator i = e.list().begin(); i != e.list().end(); ++i) {
                lst.push_back( entryToJson(*i) );
            }
            return lst;
        case entry::dictionary_t:
            for (entry::dictionary_type::const_iterator i = e.dict().begin(); i != e.dict().end(); ++i) {
                o.push_back(Pair(i->first, entryToJson(i->second)));
            }
            return o;
        default:
            return string("<uninitialized>");
    }
}

entry jsonToEntry(const Value &v)
{
    entry::list_type lst;
    entry::dictionary_type dict;

    switch( v.type() ) {
        case int_type:
            return v.get_int();
        case str_type:
            return v.get_str();
        case array_type:
            for (Array::const_iterator i = v.get_array().begin(); i != v.get_array().end(); ++i) {
                lst.push_back( jsonToEntry(*i) );
            }
            return lst;
        case obj_type:
            for (Object::const_iterator i = v.get_obj().begin(); i != v.get_obj().end(); ++i) {
                dict[ i->name_ ] = jsonToEntry(i->value_);
            }
            return dict;
        default:
            return string("<uninitialized>");
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
    string strValue    = params[3].get_str();
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

    int seq = params[5].get_int();

    if( !multi && strUsername != strSigUser )
        throw JSONRPCError(RPC_WALLET_ERROR, "Username must be the same as sig_user for single");

    entry value = entry::string_type(strValue);
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
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        ses->dht_putData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), k);
    }

    // post to dht as well
    ses->dht_putData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), k);

    // is this a reply? notify
    if( strReplyN.length() ) {
        ses->dht_putData(strReplyN, string("replies")+strReplyK, true,
                         v, strUsername, GetAdjustedTime(), k);
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
                                 v, strUsername, GetAdjustedTime(), k);
            } else if( token.at(0) == '@') {
                ses->dht_putData(word, "mention", true,
                                 v, strUsername, GetAdjustedTime(), k);
            }
        }
    }

    return entryToJson(v);
}

Value newdirectmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
            "newdirectmessage <from> <k> <to> <msg>\n"
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
    if( !acceptSignedPost(buf.data(),buf.size(),strFrom,k,errmsg) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strFrom);
    h.add_piece(k,buf.data(),buf.size());

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

    entry v;
    if( !createSignedUserpost(v, strUsername, k, "",
                              vrt.find_key("userpost"), vrt.find_key("sig_userpost"), NULL,
                              std::string(""), 0) )
        throw JSONRPCError(RPC_INTERNAL_ERROR,"error signing post with private key of user");

    vector<char> buf;
    bencode(std::back_inserter(buf), v);

    std::string errmsg;
    if( !acceptSignedPost(buf.data(),buf.size(),strUsername,k,errmsg) )
        throw JSONRPCError(RPC_INVALID_PARAMS,errmsg);

    torrent_handle h = startTorrentUser(strUsername);
    if( h.is_valid() ) {
        // if member of torrent post it directly
        h.add_piece(k,buf.data(),buf.size());
    } else {
        // TODO: swarm resource forwarding not implemented
        ses->dht_putData(strUsername, "swarm", false,
                         v, strUsername, GetAdjustedTime(), k);
    }

    // post to dht as well
    ses->dht_putData(strUsername, string("post")+strK, false,
                     v, strUsername, GetAdjustedTime(), k);

    return entryToJson(v);
}

