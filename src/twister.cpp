#include "twister.h"

#include "main.h"
#include "init.h"

#include <boost/filesystem.hpp>

const string strTwisterMessageMagic = "twister Signed Message:\n";

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
static session *ses = NULL;

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
            , alert::all_categories
                    & ~(alert::dht_notification
                    + alert::progress_notification
                    + alert::debug_notification
                    + alert::stats_notification)
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

void startSessionTorrent(boost::thread_group& threadGroup)
{
    printf("startSessionTorrent (waiting for external IP)\n");

    threadGroup.create_thread(boost::bind(&ThreadWaitExtIP));
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

std::string createSignature(std::string &strMessage, std::string &strUsername)
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
    ss << strTwisterMessageMagic;
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
    ss << strTwisterMessageMagic;
    ss << strMessage;

    CPubKey pubkeyRec;
    if (!pubkeyRec.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkeyRec.GetID() == pubkey.GetID());
}
