// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "base58.h"
#include "bitcoinrpc.h"
#include "db.h"
#include "init.h"
#include "net.h"
#include "wallet.h"
#include "twister.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const Object& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));
    out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        out.push_back(Pair("type", GetTxnOutputType(TX_NONSTANDARD)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry)
{
    entry.push_back(Pair("txid", tx.GetUsernameHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("message", tx.message.ExtractPushDataString(0)));
    entry.push_back(Pair("username", tx.userName.ExtractPushDataString(0)));
    std::vector< std::vector<unsigned char> > vData;
    if( tx.pubKey.ExtractPushData(vData) ) {
        Array o;
        BOOST_FOREACH(std::vector<unsigned char> vch, vData) {
          o.push_back(HexStr(vch));
        }
        entry.push_back(Pair("pubKey", o));
    }
    entry.push_back(Pair("nonce", (int) tx.nNonce));

    if (hashBlock != 0)
    {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain())
            {
                entry.push_back(Pair("height", pindex->nHeight));
                entry.push_back(Pair("confirmations", 1 + nBestHeight - pindex->nHeight));
                entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
                entry.push_back(Pair("blocktime", (boost::int64_t)pindex->nTime));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction <username> [verbose=0]\n"
            "If verbose=0, returns a string that is\n"
            "serialized, hex-encoded data for <txid>.\n"
            "If verbose is non-zero, returns an Object\n"
            "with information about transaction.");

    //uint256 hash = ParseHashV(params[0], "parameter 1");
    std::string username = params[0].get_str();

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(username, tx, hashBlock))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    string strHex = HexStr(ssTx.begin(), ssTx.end());

    if (!fVerbose)
        return strHex;

    Object result;
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

Value createrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2 && params.size() != 3))
        throw runtime_error(
            "createrawtransaction <username> <pubKey> [signedByOldKey]\n"
            "Create a transaction registering a new user\n"
            "Returns hex-encoded raw transaction.\n"
            "it is not stored in the wallet or transmitted to the network.");

    CTransaction rawTx;

    if (params[0].type() != str_type)
      throw JSONRPCError(RPC_INVALID_PARAMETER, "username must be string");
    string username = params[0].get_str();
    rawTx.userName = CScript() << vector<unsigned char>((const unsigned char*)username.data(), (const unsigned char*)username.data() + username.size());

    vector<unsigned char> vch(ParseHexV(params[1], "pubkey"));
    CPubKey pubkey(vch);
    if( !pubkey.IsValid() )
      throw JSONRPCError(RPC_INTERNAL_ERROR, "pubkey is not valid");

    rawTx.pubKey << vch;
    if( params.size() > 2) {
        vector<unsigned char> vchSign(ParseHexV(params[2], "signedByOldKey"));
        rawTx.pubKey << vchSign;
    }

    DoTxProofOfWork(rawTx);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    return HexStr(ss.begin(), ss.end());
}

Value decoderawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decoderawtransaction <hex string>\n"
            "Return a JSON object representing the serialized, hex-encoded transaction.");

    vector<unsigned char> txData(ParseHexV(params[0], "argument"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    Object result;
    TxToJSON(tx, 0, result);

    return result;
}

Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "sendrawtransaction <hex string>\n"
            "Submits raw transaction (serialized, hex-encoded) to local node and network.");

    // parse hex string from parameter
    vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 hashTx = tx.GetHash();

    bool fHave = false;
    uint256 hashBlock;
    CTransaction tx2;
    fHave = GetTransaction(tx.GetUsername(), tx2, hashBlock);

    // treat replacement as !fHave
    if( fHave && verifyDuplicateOrReplacementTx(tx, false, true) ) {
        printf("sendrawtransaction: is ReplacementTx true\n");
        fHave = false;
    }

    if (!fHave) {
        // push to local node
        CValidationState state;
        if (!mempool.accept(state, tx, false, NULL))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX rejected"); // TODO: report validation state
    }
    if (fHave) {
        if (hashBlock != uint256())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "transaction already in block chain");
        if (tx.GetHash() != tx2.GetHash())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "conflict transaction detected (same user, different tx)");
        // Not in block, but already in the memory pool; will drop
        // through to re-relay it.
    } else {
        SyncWithWallets(hashTx, tx, NULL, true);
    }
    RelayTransaction(tx, hashTx);

    return hashTx.GetHex();
}

Value sendnewusertransaction(const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
      throw runtime_error(
          "sendnewusertransaction <username>\n"
          "Send a transaction registering a previously created new user\n"
          "using createwalletuser or imported to the wallet\n"
          "Submits raw transaction (serialized, hex-encoded) to local node and network.");

  if (params[0].type() != str_type)
    throw JSONRPCError(RPC_INVALID_PARAMETER, "username must be string");
  string strUsername = params[0].get_str();

  CKeyID oldKeyID;
  bool replaceKey = pwalletMain->GetKeyIdBeingReplaced(strUsername, oldKeyID);

  CKeyID keyID;
  if( !pwalletMain->GetKeyIdFromUsername(strUsername, keyID) )
    throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: username must exist in wallet");

  CPubKey pubkey;
  if( !pwalletMain->GetPubKey(keyID, pubkey) )
    throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: no public key found");

  // [MF] prevent redoing POW and resending an existing transaction
  CTransaction txOut;
  uint256 hashBlock;
  bool userInTxIndex = GetTransaction(strUsername, txOut, hashBlock);
  if( !replaceKey && userInTxIndex )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: this username exists in tx database");
  if( replaceKey && !userInTxIndex )
      throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Error: key replacemente requires old key in tx database");

  Array createTxParams;
  createTxParams.push_back(strUsername);
  createTxParams.push_back(HexStr(pubkey));
  if( replaceKey ) {
    string newPubKey((const char *)pubkey.begin(), static_cast<size_t>(pubkey.size()));
    string signedByOldKey;
    signedByOldKey = createSignature(newPubKey, oldKeyID);
    createTxParams.push_back(HexStr(signedByOldKey));
  }
  Value txValue = createrawtransaction(createTxParams, false);

  if( replaceKey ) {
      pwalletMain->ForgetReplacementMap(strUsername);
  }

  std::string strTxHex = txValue.get_str();
  Array sendTxParams;
  sendTxParams.push_back(strTxHex);
  return sendrawtransaction(sendTxParams, false);
}

