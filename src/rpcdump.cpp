// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <fstream>

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"
#include "twister.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/variant/get.hpp>
#include <boost/algorithm/string.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

void EnsureWalletIsUnlocked();

std::string static EncodeDumpTime(int64 nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64 static DecodeDumpTime(const std::string &str) {
    static boost::posix_time::time_input_facet facet("%Y-%m-%dT%H:%M:%SZ");
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    const std::locale loc(std::locale::classic(), &facet);
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) | 
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "importprivkey <bitcoinprivkey> <username> [rescan=true] [allow_new_user=false]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    string strSecret = params[0].get_str();
    string strUsername = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    bool fAllowNewUser = false;
    if (params.size() > 3)
        fAllowNewUser = params[3].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);
    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CKey key = vchSecret.GetKey();
    CPubKey pubkey = key.GetPubKey();
    CKeyID vchAddress = pubkey.GetID();

    CPubKey pubkeyInDb;
    bool userExists = getUserPubKey(strUsername, pubkeyInDb);
    if( !userExists && !fAllowNewUser ) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "User must exist (or allow_new_user flag must be set)");
    }

    if( userExists && pubkey != pubkeyInDb ) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key mismatch to existing public key (wrong username?)");
    }

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress))
            return Value::null;

        pwalletMain->mapKeyMetadata[vchAddress] = CKeyMetadata(GetTime(), strUsername);

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        if (fRescan) {
            // [MF] TODO: rescan could have a different meaning, like rescaning all DM
            // of already followed users.
        }
    }

    return Value::null;
}

Value importwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet).");

    EnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64 nTimeBegin = pindexBest->nTime;

    bool fGood = true;

    while (file.good()) {
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(vstr[0]))
            continue;
        CKey key = vchSecret.GetKey();
        CPubKey pubkey = key.GetPubKey();
        CKeyID keyid = pubkey.GetID();
        if (pwalletMain->HaveKey(keyid)) {
            printf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString().c_str());
            continue;
        }
        int64 nTime = DecodeDumpTime(vstr[1]);
        std::string strUsername;
        bool fUsername = false;
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (boost::algorithm::starts_with(vstr[nStr], "username=")) {
                strUsername = DecodeDumpString(vstr[nStr].substr(9));
                fUsername = true;
            }
        }
        printf("Importing %s (username=%s)...\n", CBitcoinAddress(keyid).ToString().c_str(),
               strUsername.c_str());
        if (!fUsername) {
          printf("Missing username, skipping.\n");
          fGood = false;
          continue;
        }
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime;
        pwalletMain->mapKeyMetadata[keyid].username = strUsername;
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();

    CBlockIndex *pindex = pindexBest;
    while (pindex && pindex->pprev && pindex->nTime > nTimeBegin - 7200)
        pindex = pindex->pprev;

    printf("Rescanning last %i blocks\n", pindexBest->nHeight - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex);
    pwalletMain->ReacceptWalletTransactions();
    pwalletMain->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <username>\n"
            "Reveals the private key corresponding to <username>.");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    CKeyID keyID;
    if (!pwalletMain->GetKeyIdFromUsername(strUsername, keyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Username not found");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for username " + strUsername + " is not known");
    return CBitcoinSecret(vchSecret).ToString();
}

Value dumppubkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumppubkey <username>\n"
            "Returns the public key corresponding to <username> (empty if user doesn't exist)");

    string strUsername = params[0].get_str();

    CPubKey pubkey;
    bool gotKey = getUserPubKey(strUsername, pubkey);

    if( !gotKey ) {
        return "";
    }

    string strPubkey = string( reinterpret_cast<const char *>(pubkey.begin()), pubkey.size());
    return HexStr(strPubkey);
}


Value dumpwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format.");

    EnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64> mapKeyBirth;
    pwalletMain->GetKeyBirthTimes(mapKeyBirth);

    // sort time/key pairs
    std::vector<std::pair<int64, CKeyID> > vKeyBirth;
    for (std::map<CKeyID, int64>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by Twister %s (%s)\n", CLIENT_BUILD.c_str(), CLIENT_DATE.c_str());
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()).c_str());
    file << strprintf("# * Best block at time of backup was %i (%s),\n", nBestHeight, hashBestChain.ToString().c_str());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(pindexBest->nTime).c_str());
    file << "\n";
    for (std::vector<std::pair<int64, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = CBitcoinAddress(keyid).ToString();
        CKey key;
        if (pwalletMain->GetKey(keyid, key)) {
            if (pwalletMain->mapKeyMetadata.count(keyid)) {
                file << strprintf("%s %s username=%s # addr=%s\n",
                                  CBitcoinSecret(key).ToString().c_str(),
                                  strTime.c_str(),
                                  EncodeDumpString(pwalletMain->mapKeyMetadata[keyid].username).c_str(), strAddr.c_str());
            } else {
                file << strprintf("%s %s noname=1 # addr=%s\n",
                                  CBitcoinSecret(key).ToString().c_str(),
                                  strTime.c_str(), strAddr.c_str());
            }
        }
    }
    file << "\n";
    file << "# End of dump\n";
    file.close();
    return Value::null;
}

Value testvector(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "testvector <username>\n"
            "Returns encryption testvectors using <username> private key");

    EnsureWalletIsUnlocked();
    Object obj;

    string strUsername = params[0].get_str();

    CKeyID keyID;
    bool keyInWallet = pwalletMain->GetKeyIdFromUsername(strUsername, keyID);
    if( !keyInWallet ) {
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: no such user in wallet");
    }
    
    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: could not obtain privkey");
    obj.push_back(Pair("secret",CBitcoinSecret(key).ToString()));
    
    CPubKey pubkey;
    getUserPubKey(strUsername, pubkey);

    string strPubkey = string( reinterpret_cast<const char *>(pubkey.begin()), pubkey.size());
    obj.push_back(Pair("pubkey",HexStr(strPubkey)));
    
    CHashWriter ssMagic(SER_GETHASH, 0);
    ssMagic << strMessageMagic;
    obj.push_back(Pair("hashMagic",ssMagic.GetHash().GetHex()));

    string plainText = "The quick brown fox jumps over the lazy dog";
    obj.push_back(Pair("plaintext",plainText));
    
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << plainText;
    
    uint256 hash = ss.GetHash();
    obj.push_back(Pair("hash",hash.GetHex()));
    
    vector<unsigned char> vchSig;
    if (!key.SignCompact(hash, vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    CPubKey pubkeyRec;
    if (!pubkeyRec.RecoverCompact(hash, vchSig) ||
        pubkeyRec.GetID() != pubkey.GetID() )
       throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Check Sign failed");

    obj.push_back(Pair("sign",HexStr(vchSig)));

    ecies_secure_t sec;
    bool encrypted = pubkey.Encrypt(plainText, sec);

    if( encrypted ) {
        Object objSec;
        objSec.push_back(Pair("key",HexStr(sec.key)));
        objSec.push_back(Pair("mac",HexStr(sec.mac)));
        objSec.push_back(Pair("orig",(uint64_t)sec.orig));
        objSec.push_back(Pair("body",HexStr(sec.body)));
        obj.push_back(Pair("sec",objSec));
    }

    return obj;
}

