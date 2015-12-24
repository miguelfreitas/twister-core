// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"
#include "main.h"
#include "twister.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::string HelpRequiringPassphrase()
{
    return pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsSpamMessage())
        entry.push_back(Pair("generated", true));
    if (confirms)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", (boost::int64_t)(mapBlockIndex[wtx.hashBlock]->nTime)));
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (boost::int64_t)wtx.nTimeReceived));
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    bool usingProxy = GetProxy(NET_IPV4, proxy);

    Object obj;
    obj.push_back(Pair("version",       (int)CLIENT_VERSION));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("timeoffset",    (boost::int64_t)GetTimeOffset()));
    {
        LOCK(cs_main);
        obj.push_back(Pair("connections",   (int)vNodes.size()));
        obj.push_back(Pair("addrman_total", (int)addrman.size()));
        obj.push_back(Pair("addrman_get",   (int)addrman.GetAddr().size()));
    }
    boost::int64_t dht_global_nodes;
    obj.push_back(Pair("dht_nodes",     getDhtNodes(&dht_global_nodes)));
    obj.push_back(Pair("dht_global_nodes", dht_global_nodes));
    obj.push_back(Pair("proxy",         (proxy.first.IsValid() ? proxy.first.ToStringIPPort() : string())));
    if( !usingProxy ) {
        obj.push_back(Pair("ext_port1", GetListenPort()));
        obj.push_back(Pair("ext_port2", GetListenPort()+LIBTORRENT_PORT_OFFSET));
    }
    {
        LOCK(cs_main);
        obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
        obj.push_back(Pair("testnet",       TestNet()));
        {
            LOCK(pwalletMain->cs_wallet);
            if (pwalletMain->IsCrypted())
                obj.push_back(Pair("unlocked_until", (boost::int64_t)nWalletUnlockTime));
        }
        obj.push_back(Pair("public_server_mode", GetBoolArg("-public_server_mode",false)));
        obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    }

    const CNetAddr paddrPeer("8.8.8.8");
    CAddress addr( GetLocalAddress(&paddrPeer) );
    obj.push_back(Pair("ext_addr_net1", addr.IsValid() ? addr.ToStringIP() : string()) );

    Object torrent_stats = getLibtorrentSessionStatus();
    obj.insert( obj.end(), torrent_stats.begin(), torrent_stats.end() );

    return obj;
}



Value createwalletuser(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "createwalletuser <username> [replacekey]\n"
            "Create a new key pair for user and add it to wallet\n"
            "Use sendnewusertransaction to publish it to the network.\n"
            "Returns key secret (keep it safe)");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();

    bool replaceKey = false;
    if (params.size() > 1)
        replaceKey = params[1].get_bool();

    CKeyID keyID;
    bool keyInWallet = pwalletMain->GetKeyIdFromUsername(strUsername, keyID);
    if( keyInWallet && !replaceKey )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: this username exists in wallet");
    if( !keyInWallet && replaceKey )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: replacekey given but old key not in wallet");

    CTransaction txOut;
    uint256 hashBlock;
    if( GetTransaction(strUsername, txOut, hashBlock) && !replaceKey )
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: this username exists in tx database");

    if( replaceKey && !pwalletMain->MoveKeyForReplacement(strUsername) )
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: moving key for replacement");

    // Generate a new key that is added to wallet
    CPubKey newKey = pwalletMain->GenerateNewKey(strUsername);
    keyID = newKey.GetID();

    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: could not obtain just created privkey?!");
    return CBitcoinSecret(vchSecret).ToString();
}


Value listwalletusers(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "listwalletusers\n"
            "Returns the list of wallet usernames.");

    // Find all addresses that have the given account
    Array ret;
    
    // Always return an empty array on a public server
    if(GetBoolArg("-public_server_mode",false))
        return ret;
    
    LOCK(pwalletMain->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CKeyID, CKeyMetadata)& item, pwalletMain->mapKeyMetadata)
    {
        if (item.second.username[0] != '*')
            ret.push_back(item.second.username);
    }
    return ret;
}

/* [mf] no use for setting/getting defaultuser, it just adds confusion.
   all commands should receive user as parameter (including the user for spammsg).
*/
#if 0
Value setdefaultuser(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setdefaultuser <username>\n"
            "Set default user to use (must exist)");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();

    CKeyID keyID;
    if( !pwalletMain->GetKeyIdFromUsername(strUsername, keyID) )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: username does not exist in wallet");

    CPubKey vchPubKey;
    if( !pwalletMain->GetPubKey( keyID, vchPubKey) )
      throw JSONRPCError(RPC_WALLET_ERROR, "Error recovering pubkey from wallet");

    if( !pwalletMain->SetDefaultKey(vchPubKey) )
        throw JSONRPCError(RPC_WALLET_ERROR, "Error setting default key");

    return Value();
}

Value getdefaultuser(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdefaultuser\n"
            "Get default user being used");

    EnsureWalletIsUnlocked();

    CPubKey vchPubKey = pwalletMain->vchDefaultKey;

    if( !vchPubKey.IsValid() )
      throw JSONRPCError(RPC_WALLET_ERROR, "Error: default user key is invalid");

    CKeyID keyID = vchPubKey.GetID();
    std::string username;
    if( !pwalletMain->GetUsernameFromKeyId(keyID, username) )
        throw JSONRPCError(RPC_WALLET_ERROR, "Error converting keyID to username");

    return username;
}
#endif

Value signmessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <username> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked();

    string strUsername = params[0].get_str();
    string strMessage = params[1].get_str();

    CKeyID keyID;
    if( !pwalletMain->GetKeyIdFromUsername(strUsername, keyID) )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: no such user in wallet");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <username> <signature> <message>\n"
            "Verify a signed message");

    string strUsername = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CPubKey pubkey;
    {
      CKeyID keyID;
      if( pwalletMain->GetKeyIdFromUsername(strUsername, keyID) ) {
        if( !pwalletMain->GetPubKey(keyID, pubkey) )
          throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: failed to read pubkey from wallet");
      }
    }

    if( !pubkey.IsValid() ) {
      CTransaction txOut;
      uint256 hashBlock;
      if( !GetTransaction(strUsername, txOut, hashBlock) )
          throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: this username does not exist in tx database");

      std::vector< std::vector<unsigned char> > vData;
      if( !txOut.pubKey.ExtractPushData(vData) || vData.size() < 1 )
          throw JSONRPCError(RPC_INTERNAL_ERROR, "Error: error extracting pubkey from tx");
      pubkey = CPubKey(vData[0]);
      if( !pubkey.IsValid() )
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Error: invalid pubkey data from tx");
    }

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkeyRec;
    if (!pubkeyRec.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkeyRec.GetID() == pubkey.GetID());
}


void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
    //bool fAllAccounts = (strAccount == string("*"));

    // Sent
    //if ((fAllAccounts || strAccount == strSentAccount))
    {
        Object entry;
        //entry.push_back(Pair("account", strSentAccount));
        //entry.push_back(Pair("address", CBitcoinAddress(s.first).ToString()));
        if (fLong)
            WalletTxToJSON(wtx, entry);
        ret.push_back(entry);
    }

    if (wtx.GetDepthInMainChain() >= nMinDepth)
    {
        Object entry;
        //entry.push_back(Pair("account", account));
        //entry.push_back(Pair("address", CBitcoinAddress(r.first).ToString()));
        if (fLong)
            WalletTxToJSON(wtx, entry);
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    Array ret;

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

Value listsinceblock(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;

    if (params.size() > 0)
    {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    int depth = pindex ? (1 + nBestHeight - pindex->nHeight) : -1;

    Array transactions;

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions);
    }

    uint256 lastblock;

    if (target_confirms == 1)
    {
        lastblock = hashBestChain;
    }
    else
    {
        int target_height = pindexBest->nHeight + 1 - target_confirms;

        CBlockIndex *block;
        for (block = pindexBest;
             block && block->nHeight > target_height;
             block = block->pprev)  { }

        lastblock = block ? block->GetBlockHash() : 0;
    }

    Object ret;
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

Value gettransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about in-wallet transaction <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;
    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash];

    //entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));

    WalletTxToJSON(wtx, entry);

    Array details;
    ListTransactions(wtx, "*", 0, false, details);
    entry.push_back(Pair("details", details));

    return entry;
}


Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies twisterwallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return Value::null;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = 0;
    pWallet->Lock();
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    int64 nSleepTime = params[1].get_int64();
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = GetTime() + nSleepTime;
    RPCRunLater("lockwallet", boost::bind(LockWallet, pwalletMain), nSleepTime);

    return Value::null;
}


Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return Value::null;
}


Value walletlock(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; Twister server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup.";
}

class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
        obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }
};


