// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"
#include "softcheckpoint.h"

using namespace json_spirit;
using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    Array txs;
    Array txuserhashes;
    Array usernames;
    std::string spamMessage;
    std::string spamUser;
    BOOST_FOREACH(const CTransaction&tx, block.vtx) {
        txs.push_back(tx.GetHash().GetHex());
        if( tx.IsSpamMessage() ) {
          spamMessage = tx.message.ExtractPushDataString(0);
          spamUser = tx.userName.ExtractPushDataString(0);
        } else {
          txuserhashes.push_back(tx.GetUsernameHash().GetHex());
          usernames.push_back(tx.userName.ExtractSmallString());
        }
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("spamMessage", spamMessage));
    result.push_back(Pair("spamUser", spamUser));
    result.push_back(Pair("userhashes", txuserhashes));
    result.push_back(Pair("usernames", usernames));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = blockindex->GetNextInMainChain();
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}

Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best (tip) block in the longest block chain.");

    return hashBestChain.GetHex();
}

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    if (pblockindex == NULL) {
        string errormsg = "getblockhash internal error: pblockindex == NULL. consider reindexing blocks (program may crash)";
        printf("%s\n",errormsg.c_str());
        throw runtime_error(errormsg);
    }
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [verbose=true]\n"
            "If verbose is false, returns a string that is serialized, hex-encoded data for block <hash>.\n"
            "If verbose is true, returns an Object with information about block <hash>."
        );

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    ReadBlockFromDisk(block, pblockindex);

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}


Value verifychain(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "verifychain [check level] [num blocks]\n"
            "Verifies blockchain database.");

    int nCheckLevel = GetArg("-checklevel", 3);
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return VerifyDB(nCheckLevel, nCheckDepth);
}


Value getlastsoftcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getlastsoftcheckpoint\n"
            "Returns votes of last soft checkpoint.");

    Object result;
    
    int height;
    uint256 hash;
    std::set<std::string> usernamesSet;
    if( SoftCheckpoints::GetLastCPVotes(height, hash, usernamesSet) ) {
        result.push_back(Pair("height", height));
        result.push_back(Pair("hash", hash.GetHex()));
        
        Array usernames;
        BOOST_FOREACH(const std::string &user, usernamesSet) {
            usernames.push_back(user);
        }
        result.push_back(Pair("usernames", usernames));
    }
    
    return result;
}
