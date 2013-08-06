#include "twister.h"

#include "main.h"
#include "init.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

#include <boost/filesystem.hpp>

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

using namespace libtorrent;
static session *ses = NULL;

static CCriticalSection cs_dhtgetMap;
static map<uint256, alert_manager*> m_dhtgetMap;


uint256 dhtTargetHash(std::string const &username, std::string const &resource, std::string const &type)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << username;
    ss << resource;
    ss << type;

    return ss.GetHash();
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
            , ipStr.size() ? ipStr.c_str() : NULL );

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

    ses->start_dht();

    //ses->set_settings(settings);

    printf("libtorrent + dht started\n");
}

void ThreadMaintainDHTNodes()
{
    RenameThread("maintain-dht-nodes");

    while(1) {
        MilliSleep(5000);

        if( ses ) {
            session_status ss = ses->status();
            if( ss.dht_nodes == 0 && vNodes.size() ) {
                printf("ThreadMaintainDHTNodes: no dht_nodes, trying to add some...\n");
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes) {
                    BOOST_FOREACH(CAddress const &knownAddr, pnode->setAddrKnown) {
                        std::string addr = knownAddr.ToStringIP();
                        int port = knownAddr.GetPort() + LIBTORRENT_PORT_OFFSET;
                        printf("Adding dht node %s:%d\n", addr.c_str(), port);
                        ses->add_dht_node(std::pair<std::string, int>(addr, port));
                    }
                }
            }
        }
    }
}

void ThreadSessionAlerts()
{
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
                                    uint256 th = dhtTargetHash(n->string(), r->string(), t->string());

                                    LOCK(cs_dhtgetMap);
                                    std::map<uint256, alert_manager*>::iterator mi = m_dhtgetMap.find(th);
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

                /*
                save_resume_data_alert const* rd = alert_cast<save_resume_data_alert>(*i);
                if (rd) {
                    if (!rd->resume_data) continue;

                    torrent_handle h = rd->handle;
                    torrent_status st = h.status(torrent_handle::query_save_path);
                    std::vector<char> out;
                    bencode(std::back_inserter(out), *rd->resume_data);
                    save_file(combine_path(st.save_path, combine_path(".resume", to_hex(st.info_hash.to_string()) + ".resume")), out);
                }
                */
        }
    }
}


void startSessionTorrent(boost::thread_group& threadGroup)
{
    printf("startSessionTorrent (waiting for external IP)\n");

    threadGroup.create_thread(boost::bind(&ThreadWaitExtIP));
    threadGroup.create_thread(boost::bind(&ThreadMaintainDHTNodes));
    threadGroup.create_thread(boost::bind(&ThreadSessionAlerts));
}

void stopSessionTorrent()
{
    if( ses ){
            ses->pause();

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


bool verifySignature(std::string const &strMessage, std::string const &strUsername, std::string const &strSign)
{
    CPubKey pubkey;
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
          //printf("verifySignature: user unknown '%s'\n", strUsername.c_str());
          return false;
      }

      std::vector< std::vector<unsigned char> > vData;
      if( !txOut.pubKey.ExtractPushData(vData) || vData.size() < 1 ) {
          printf("verifySignature: broken pubkey for user '%s'\n", strUsername.c_str());
          return false;
      }
      pubkey = CPubKey(vData[0]);
      if( !pubkey.IsValid() ) {
          printf("verifySignature: invalid pubkey for user '%s'\n", strUsername.c_str());
          return false;
      }
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

int getBestHeight()
{
    return nBestHeight;
}

Value dhtput(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 5 || params.size() > 6)
        throw runtime_error(
            "dhtput <username> <resource> <s(ingle)/m(ulti)> <value> <sig_user> <seq>\n"
            "Sign a message with the private key of an address");

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

    int seq = -1;
    if( params.size() == 6 ) seq = atoi( params[5].get_str().c_str() );

    if( !multi && strUsername != strSigUser )
        throw JSONRPCError(RPC_WALLET_ERROR, "Username must be the same as sig_user for single");

    entry value = entry::string_type(strValue);
    int timeutc = time(NULL);

    ses->dht_putData(strUsername, strResource, multi, value, strSigUser, timeutc, seq);
    return Value();
}

Value dhtget(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "dhtget <username> <resource> <s(ingle)/m(ulti)>\n"
            "Sign a message with the private key of an address");

    string strUsername = params[0].get_str();
    string strResource = params[1].get_str();
    string strMulti    = params[2].get_str();

    bool multi = (strMulti == "m");

    alert_manager am(10, alert::dht_notification);
    uint256 th = dhtTargetHash(strUsername,strResource,strMulti);

    {
        LOCK(cs_dhtgetMap);
        m_dhtgetMap[th] = &am;
    }

    ses->dht_getData(strUsername, strResource, multi);

    Value ret;

    if( am.wait_for_alert(seconds(10)) ) {
        std::auto_ptr<alert> a(am.get());

        dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(&(*a));
        entry const *p = rd->m_lst.begin()->find_key("p");

        // FIXME: temporary. implement proper parsing/conversion
        ret = rd->m_lst.begin()->find_key("sig_p")->string();
    }

    {
        LOCK(cs_dhtgetMap);
        m_dhtgetMap.erase(th);
    }

    return ret;
}

