// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "core.h"
#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"

#include <list>

class CWallet;
class CBlock;
class CBlockIndex;
class CKeyItem;

class CAddress;
class CInv;
class CNode;

struct CBlockIndexWorkComparator;

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 50000;
/** The maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
/** The maximum size for transactions we're willing to relay/mine */
//static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN/5;
static const unsigned int MAX_STANDARD_TX_SIZE = (140+16+512+32); //msg+user+key+spare
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** The maximum number of orphan transactions kept in memory */
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8) */
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;
/** No amount larger than this (in satoshi) is valid */
static const int64 MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. */
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** Default amount of block size reserved for high-priority transactions (in bytes) */
static const int DEFAULT_BLOCK_PRIORITY_SIZE = 27000;
/** The maximum size for spam messages */
static const int MAX_SPAM_MSG_SIZE = 140;
/** The maximum size for username */
static const unsigned int MAX_USERNAME_SIZE = 16;


extern CScript COINBASE_FLAGS;






extern CCriticalSection cs_main;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::vector<CBlockIndex*> vBlockIndexByHeight;
extern std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern uint256 nBestChainWork;
extern uint256 nBestInvalidWork;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern uint64 nLastBlockTx;
extern uint64 nLastBlockSize;
extern const std::string strMessageMagic;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;
extern bool fImporting;
extern bool fReindex;
extern bool fBenchmark;
extern int nScriptCheckThreads;
extern unsigned int nCoinCacheSize;
extern bool fHaveGUI;

// Settings
extern int64 nTransactionFee;

extern CCriticalSection cs_spamMessages;
static const string strSpamMessage = "Promoted posts are needed to run the network infrastructure. If you want to help, start generating blocks and advertise. [en]";
extern std::list<string> spamMessages;
extern string strSpamUser;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64 nMinDiskSpace = 52428800;


class CCoinsDB;
class CBlockTreeDB;
struct CDiskBlockPos;
class CCoins;
class CTxUndo;
class CCoinsView;
class CCoinsViewCache;
class CValidationState;

struct CBlockTemplate;

/** Register a wallet to receive updates from core */
void RegisterWallet(CWallet* pwalletIn);
/** Unregister a wallet from core */
void UnregisterWallet(CWallet* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllWallets();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const uint256 &hash, const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd);

/** Process an incoming block */
bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp = NULL);
/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64 nAdditionalBytes = 0);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Import blocks from an external file */
bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp = NULL);
/** Initialize a new block tree database + block data on disk */
bool InitBlockIndex();
/** Load the block tree and coins database from disk */
bool LoadBlockIndex();
/** Unload database information */
void UnloadBlockIndex();
/** Verify consistency of the block and coin databases */
bool VerifyDB(int nCheckLevel, int nCheckDepth);
/** Print the loaded block tree */
void PrintBlockTree();
/** Find a block by height in the currently-connected chain */
CBlockIndex* FindBlockByHeight(int nHeight);
/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);
/** Send queued protocol messages to be sent to a give node */
bool SendMessages(CNode* pto, bool fSendTrickle);
/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(std::vector<unsigned char> &salt);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Do mining precalculation */
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
/** Check mined block */
bool CheckWork(CBlock* pblock, CWallet& wallet);
/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
/** Calculate the minimum amount of work a received block needs, without knowing its direct parent */
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime);
/** Get the number of active peers */
int GetNumBlocksOfPeers();
/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();
/** Format a string that describes several potential problems detected by the core */
std::string GetWarnings(std::string strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const std::string &username, CTransaction &tx, uint256 &hashBlock, int maxHeight = -1);
/** Verify duplicate or replacement transactions */
bool verifyDuplicateOrReplacementTx(CTransaction &tx, bool checkDuplicate, bool checkReplacement, int maxHeight = -1, bool removeOrphan = false);
/** Connect/disconnect blocks until pindexNew is the new tip of the active block chain */
bool SetBestChain(CValidationState &state, CBlockIndex* pindexNew);
/** Find the best known block, and make it the tip of the block chain */
bool ConnectBestBlock(CValidationState &state);

void UpdateTime(CBlockHeader& block, const CBlockIndex* pindexPrev);

/** Create a new block index entry for a given block hash */
CBlockIndex * InsertBlockIndex(uint256 hash);
/** Abort with a message */
bool AbortNode(const std::string &msg);











bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    )

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }
};

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header

    IMPLEMENT_SERIALIZE(
        READWRITE(*(CDiskBlockPos*)this);
        READWRITE(VARINT(nTxOffset));
    )

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};


inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > COIN * 144 / 250;
}

bool CheckUsername(const std::string &userName, CValidationState &state);

bool TxNumToUsername(unsigned int txNum, string &username);

bool UsernameToTxNum(const string &username, int *txNum, bool last = true);

bool DoTxProofOfWork(CTransaction& tx);

// Context-independent validity checks
bool CheckTransaction(const CTransaction& tx, CValidationState& state, int maxHeight = -1);

/** Check for standard transaction types
    @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, std::string& reason);

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    IMPLEMENT_SERIALIZE(
        READWRITE(vtxundo);
    )

    bool WriteToDisk(CDiskBlockPos &pos, const uint256 &hashBlock)
    {
        // Open history file to append
        CAutoFile fileout = CAutoFile(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
        if (!fileout)
            return error("CBlockUndo::WriteToDisk() : OpenUndoFile failed");

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(Params().MessageStart()) << nSize;

        // Write undo data
        long fileOutPos = ftell(fileout);
        if (fileOutPos < 0)
            return error("CBlockUndo::WriteToDisk() : ftell failed");
        pos.nPos = (unsigned int)fileOutPos;
        fileout << *this;

        // calculate & write checksum
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << hashBlock;
        hasher << *this;
        fileout << hasher.GetHash();

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload())
            FileCommit(fileout);

        return true;
    }

    bool ReadFromDisk(const CDiskBlockPos &pos, const uint256 &hashBlock)
    {
        // Open history file to read
        CAutoFile filein = CAutoFile(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CBlockUndo::ReadFromDisk() : OpenBlockFile failed");

        // Read block
        uint256 hashChecksum;
        try {
            filein >> *this;
            filein >> hashChecksum;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Verify checksum
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << hashBlock;
        hasher << *this;
        if (hashChecksum != hasher.GetHash())
            return error("CBlockUndo::ReadFromDisk() : checksum mismatch");

        return true;
    }
};


/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree=true);
};





/** Data structure that represents a partial merkle tree.
 *
 * It respresents a subset of the txid's of a known block, in a way that
 * allows recovery of the list of txid's and the merkle root, in an
 * authenticated way.
 *
 * The encoding works as follows: we traverse the tree in depth-first order,
 * storing a bit for each traversed node, signifying whether the node is the
 * parent of at least one matched leaf txid (or a matched txid itself). In
 * case we are at the leaf level, or this bit is 0, its merkle node hash is
 * stored, and its children are not explorer further. Otherwise, no hash is
 * stored, but we recurse into both (or the only) child branch. During
 * decoding, the same depth-first traversal is performed, consuming bits and
 * hashes as they written during encoding.
 *
 * The serialization is fixed and provides a hard guarantee about the
 * encoded size:
 *
 *   SIZE <= 10 + ceil(32.25*N)
 *
 * Where N represents the number of leaf nodes of the partial tree. N itself
 * is bounded by:
 *
 *   N <= total_transactions
 *   N <= 1 + matched_transactions*tree_height
 *
 * The serialization format:
 *  - uint32     total_transactions (4 bytes)
 *  - varint     number of hashes   (1-3 bytes)
 *  - uint256[]  hashes in depth-first order (<= 32*N bytes)
 *  - varint     number of bytes of flag bits (1-3 bytes)
 *  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)
 * The size constraints follow from this.
 */
class CPartialMerkleTree
{
protected:
    // the total number of transactions in the block
    unsigned int nTransactions;

    // node-is-parent-of-matched-txid bits
    std::vector<bool> vBits;

    // txids and internal hashes
    std::vector<uint256> vHash;

    // flag set when encountering invalid data
    bool fBad;

    // helper function to efficiently calculate the number of nodes at given height in the merkle tree
    unsigned int CalcTreeWidth(int height) {
        return (nTransactions+(1 << height)-1) >> height;
    }

    // calculate the hash of a node in the merkle tree (at leaf level: the txid's themself)
    uint256 CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid);

    // recursive function that traverses tree nodes, storing the data as bits and hashes
    void TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch);

    // recursive function that traverses tree nodes, consuming the bits and hashes produced by TraverseAndBuild.
    // it returns the hash of the respective node.
    uint256 TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch);

public:

    // serialization implementation
    IMPLEMENT_SERIALIZE(
        READWRITE(nTransactions);
        READWRITE(vHash);
        std::vector<unsigned char> vBytes;
        if (fRead) {
            READWRITE(vBytes);
            CPartialMerkleTree &us = *(const_cast<CPartialMerkleTree*>(this));
            us.vBits.resize(vBytes.size() * 8);
            for (unsigned int p = 0; p < us.vBits.size(); p++)
                us.vBits[p] = (vBytes[p / 8] & (1 << (p % 8))) != 0;
            us.fBad = false;
        } else {
            vBytes.resize((vBits.size()+7)/8);
            for (unsigned int p = 0; p < vBits.size(); p++)
                vBytes[p / 8] |= vBits[p] << (p % 8);
            READWRITE(vBytes);
        }
    )

    // Construct a partial merkle tree from a list of transaction id's, and a mask that selects a subset of them
    CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch);

    CPartialMerkleTree();

    // extract the matching txid's represented by this partial merkle tree.
    // returns the merkle root, or 0 in case of failure
    uint256 ExtractMatches(std::vector<uint256> &vMatch);
};



/** Functions for disk access for blocks */
bool WriteBlockToDisk(CBlock& block, CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);


/** Functions for validating blocks and updating the block tree */

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool DisconnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool fJustCheck = false);

// Apply the effects of this block (with given index) on the UTXO set represented by coins
bool ConnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool fJustCheck = false);

// Add this block to the block index, and if necessary, switch the active block chain to this
bool AddToBlockIndex(CBlock& block, CValidationState& state, const CDiskBlockPos& pos);

// Context-independent validity checks
bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

// Store block on disk
// if dbp is provided, the file is known to already reside on disk
bool AcceptBlock(CBlock& block, CValidationState& state, CDiskBlockPos* dbp = NULL);



class CBlockFileInfo
{
public:
    unsigned int nBlocks;      // number of blocks stored in file
    unsigned int nSize;        // number of used bytes of block file
    unsigned int nUndoSize;    // number of used bytes in the undo file
    unsigned int nHeightFirst; // lowest height of block in file
    unsigned int nHeightLast;  // highest height of block in file
    uint64 nTimeFirst;         // earliest time of block in file
    uint64 nTimeLast;          // latest time of block in file

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
     )

     void SetNull() {
         nBlocks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     CBlockFileInfo() {
         SetNull();
     }

     std::string ToString() const {
         return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst).c_str(), DateTimeStrFormat("%Y-%m-%d", nTimeLast).c_str());
     }

     // update statistics (does not update nSize)
     void AddBlock(unsigned int nHeightIn, uint64 nTimeIn) {
         if (nBlocks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBlocks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBlocks++;
         if (nHeightIn > nHeightFirst)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

extern CCriticalSection cs_LastBlockFile;
extern CBlockFileInfo infoLastBlockFile;
extern int nLastBlockFile;

enum BlockStatus {
    BLOCK_VALID_UNKNOWN      =    0,
    BLOCK_VALID_HEADER       =    1, // parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_TREE         =    2, // parent found, difficulty matches, timestamp >= median previous, checkpoint
    BLOCK_VALID_TRANSACTIONS =    3, // only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids, sigops, size, merkle root
    BLOCK_VALID_CHAIN        =    4, // outputs do not overspend inputs, no double spends, coinbase output ok, immature coinbase spends, BIP30
    BLOCK_VALID_SCRIPTS      =    5, // scripts/signatures ok
    BLOCK_VALID_MASK         =    7,

    BLOCK_HAVE_DATA          =    8, // full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, // undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   24,

    BLOCK_FAILED_VALID       =   32, // stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, // descends from failed block
    BLOCK_FAILED_MASK        =   96
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    // pointer to the hash of the block, if any. memory is owned by this CBlockIndex
    const uint256* phashBlock;

    // pointer to the index of the predecessor of this block
    CBlockIndex* pprev;

    // height of the entry in the chain. The genesis block has height 0
    int nHeight;

    // Which # file this block is stored in (blk?????.dat)
    int nFile;

    // Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    // Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    // (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    uint256 nChainWork;

    // Number of transactions in this block.
    // Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    // (memory only) Number of transactions in the chain up to and including this block
    unsigned int nChainTx; // change to 64-bit type when necessary; won't happen before 2030

    // Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = 0;
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(CBlockHeader& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = 0;
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    CDiskBlockPos GetBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.nHeight        = nHeight;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    CBigNum GetBlockWork() const
    {
        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        if (bnTarget <= 0)
            return 0;
        return (CBigNum(1)<<256) / (bnTarget+1);
    }

    bool IsInMainChain() const
    {
        return nHeight < (int)vBlockIndexByHeight.size() && vBlockIndexByHeight[nHeight] == this;
    }

    CBlockIndex *GetNextInMainChain() const {
        if( !IsInMainChain() ) return NULL;
        return nHeight+1 >= (int)vBlockIndexByHeight.size() ? NULL : vBlockIndexByHeight[nHeight+1];
    }

    bool CheckIndex() const
    {
        /** Scrypt is used for block proof-of-work, but for purposes of performance the index internally uses sha256.
         *  This check was considered unneccessary given the other safeguards like the genesis and checkpoints. */
        return true;
        //return CheckProofOfWork(CBlock(GetBlockHeader()).GetPoWHash(), nBits);
    }

    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
        int64 pmedian[nMedianTimeSpan];
        int64* pbegin = &pmedian[nMedianTimeSpan];
        int64* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->GetNextInMainChain())
                return GetBlockTime();
            pindex = pindex->GetNextInMainChain();
        }
        return pindex->GetMedianTimePast();
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above
     * in the last nToCheck blocks, starting at pstart and going backwards.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, pnext=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, GetNextInMainChain(), nHeight,
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) const {
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        if (pa->GetBlockHash() < pb->GetBlockHash()) return false;
        if (pa->GetBlockHash() > pb->GetBlockHash()) return true;

        return false; // identical blocks
    }
};



/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;

    CDiskBlockIndex() {
        hashPrev = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    uint256 GetBlockHash() const
    {
        CBlockHeader block;
        block.nVersion        = nVersion;
        block.nHeight         = nHeight;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   // everything ok
        MODE_INVALID, // network rule violation (DoS value may be set)
        MODE_ERROR,   // run-time error
    } mode;
    int nDoS;
public:
    CValidationState() : mode(MODE_VALID), nDoS(0) {}
    bool DoS(int level, bool ret = false) {
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false) {
        return DoS(0, ret);
    }
    bool Error() {
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg) {
        AbortNode(msg);
        return Error();
    }
    bool IsValid() {
        return mode == MODE_VALID;
    }
    bool IsInvalid() {
        return mode == MODE_INVALID;
    }
    bool IsError() {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
};







/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:
    CBlockLocator() {}

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock);

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    /** Given a block initialises the locator to that point in the chain. */
    void Set(const CBlockIndex* pindex);
    /** Returns the distance in blocks this locator is from our chain head. */
    int GetDistanceBack();
    /** Returns the first best-chain block the locator contains. */
    CBlockIndex* GetBlockIndex();
    /** Returns the hash of the first best chain block the locator contains. */
    uint256 GetBlockHash();
    /** Returns the height of the first best chain block the locator has. */
    int GetHeight();
};








class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx; // [MF] hash is txhash again

    bool accept(CValidationState &state, CTransaction &tx, bool fLimitFree, bool* pfMissingInputs);
    bool addUnchecked(const uint256& userhash, CTransaction &tx);
    bool remove(const CTransaction &tx, bool fRecursive = false);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 txhash)
    {
        return (mapTx.count(txhash) != 0);
    }

    CTransaction& lookup(uint256 txhash)
    {
        return mapTx[txhash];
    }
};

extern CTxMemPool mempool;

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64 nTransactions;
    uint64 nTransactionOutputs;
    uint64 nSerializedSize;
    uint256 hashSerialized;
    int64 nTotalAmount;

    CCoinsStats() : nHeight(0), hashBlock(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), hashSerialized(0), nTotalAmount(0) {}
};

/** Abstract view on the open txout dataset. */
class CCoinsView
{
public:
    // Retrieve the block index whose state this CCoinsView currently represents
    virtual CBlockIndex *GetBestBlock();

    // Modify the currently active block index
    virtual bool SetBestBlock(CBlockIndex *pindex);

    // Do a bulk modification (multiple SetCoins + one SetBestBlock)
    virtual bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);

    // Calculate statistics about the unspent transaction output set
    virtual bool GetStats(CCoinsStats &stats);

    // As we use CCoinsViews polymorphically, have a virtual destructor
    virtual ~CCoinsView() {}
};

/** CCoinsView backed by another CCoinsView */
class CCoinsViewBacked : public CCoinsView
{
protected:
    CCoinsView *base;

public:
    CCoinsViewBacked(CCoinsView &viewIn);
    CBlockIndex *GetBestBlock();
    bool SetBestBlock(CBlockIndex *pindex);
    void SetBackend(CCoinsView &viewIn);
    bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);
    bool GetStats(CCoinsStats &stats);
};

/** CCoinsView that adds a memory cache for transactions to another CCoinsView */
class CCoinsViewCache : public CCoinsViewBacked
{
protected:
    CBlockIndex *pindexTip;
    std::map<uint256,CCoins> cacheCoins;

public:
    CCoinsViewCache(CCoinsView &baseIn, bool fDummy = false);

    CBlockIndex *GetBestBlock();
    bool SetBestBlock(CBlockIndex *pindex);
    bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);

    // Push the modifications applied to this cache to its base.
    // Failure to call this method before destruction will cause the changes to be forgotten.
    bool Flush();

    // Calculate the size of the cache (in number of transactions)
    unsigned int GetCacheSize();

private:
    std::map<uint256,CCoins>::iterator FetchCoins(const uint256 &txid);
};

/** CCoinsView that brings transactions from a memorypool into view.
    It does not check for spendings by memory pool transactions. */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn);
    bool GetCoins(const uint256 &txid, CCoins &coins);
    bool HaveCoins(const uint256 &txid);
};

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern CCoinsViewCache *pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern CBlockTreeDB *pblocktree;

struct CBlockTemplate
{
    CBlock block;
};






/** Used to relay blocks as header + vector<merkle branch>
 * to filtered nodes.
 */
class CMerkleBlock
{
public:
    // Public only for unit testing
    CBlockHeader header;
    CPartialMerkleTree txn;

public:
    // Public only for unit testing and relay testing
    // (not relayed)
    std::vector<std::pair<unsigned int, uint256> > vMatchedTxn;

    // Create from a CBlock, filtering transactions according to filter
    // Note that this will call IsRelevantAndUpdate on the filter for each transaction,
    // thus the filter will likely be modified.
    CMerkleBlock(const CBlock& block, CBloomFilter& filter);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(header);
        READWRITE(txn);
    )
};

#endif
