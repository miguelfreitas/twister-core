// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CORE_H
#define BITCOIN_CORE_H

#include "uint256.h"
#include "serialize.h"
#include "script.h"
#include "scrypt.h"

#include <stdio.h>

class CTransaction;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = (unsigned int) -1; }
    bool IsNull() const { return (hash == 0 && n == (unsigned int) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max());

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<unsigned int>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};




/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    int64 nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    bool IsDust(int64 nMinRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::nMinRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend,
        // so dust is a txout less than 54 uBTC
        // (5460 satoshis) with default nMinRelayTxFee
        return ((nValue*1000)/(3*((int)GetSerializeSize(SER_DISK,0)+148)) < nMinRelayTxFee);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    CScript message;
    CScript userName;
    CScript pubKey;
    unsigned int nNonce;

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(message);
        READWRITE(userName);
        READWRITE(pubKey);
        READWRITE(nNonce);
    )

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        message.clear();
        userName.clear();
        pubKey.clear();
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (message.empty() && userName.empty() && pubKey.empty());
    }

    uint256 GetHash() const;
    std::string GetUsername() const;
    uint256 GetUsernameHash() const;

    bool IsSpamMessage() const
    {
        return !message.empty();
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.message   == b.message &&
                a.userName  == b.userName &&
                a.pubKey    == b.pubKey);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    std::string ToString() const;
    void print() const;
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
private:
    CTxOut &txout;

public:
    static uint64 CompressAmount(uint64 nAmount);
    static uint64 DecompressAmount(uint64 nAmount);

    CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) { }

    IMPLEMENT_SERIALIZE(({
        if (!fRead) {
            uint64 nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } else {
            uint64 nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    });)
};

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
class CTxInUndo
{
public:
    CTxOut txout;         // the txout data before being spent
    bool fCoinBase;       // if the outpoint was the last unspent: whether it belonged to a coinbase
    unsigned int nHeight; // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version

    CTxInUndo() : txout(), fCoinBase(false), nHeight(0), nVersion(0) {}
    CTxInUndo(const CTxOut &txoutIn, bool fCoinBaseIn = false, unsigned int nHeightIn = 0, int nVersionIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), nVersion(nVersionIn) { }

    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return ::GetSerializeSize(VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion) +
               (nHeight > 0 ? ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion) : 0) +
               ::GetSerializeSize(CTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const {
        ::Serialize(s, VARINT(nHeight*2+(fCoinBase ? 1 : 0)), nType, nVersion);
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Serialize(s, CTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode), nType, nVersion);
        nHeight = nCode / 2;
        fCoinBase = nCode & 1;
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion), nType, nVersion);
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout))), nType, nVersion);
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<CTxInUndo> vprevout;

    IMPLEMENT_SERIALIZE(
        READWRITE(vprevout);
    )
};


/** pruned version of CTransaction: only retains metadata and unspent transaction outputs
 *
 * That is: userName and pubKey
 *
 * Serialized format:
 * - VARINT(nVersion)
 * - userName
 * - pubKey
 * - VARINT(nHeight)
 *
 */
class CCoins
{
public:
    CScript userName;
    CScript pubKey;

    // at which height this transaction was included in the active block chain
    int nHeight;

    // version of the CTransaction; accesses to this value should probably check for nHeight as well,
    // as new tx version will probably only be introduced at certain heights
    int nVersion;

    // construct a CCoins from a CTransaction, at a given height
    CCoins(const CTransaction &tx, int nHeightIn) :
        userName(tx.userName), pubKey(tx.pubKey), nHeight(nHeightIn), nVersion(tx.nVersion) { }

    // empty constructor
    CCoins() : userName(), pubKey(), nHeight(0), nVersion(0) { }

    // remove spent outputs at the end of vout
    void Cleanup() {
    }

    void swap(CCoins &to) {
        std::swap(to.userName, userName);
        std::swap(to.pubKey, pubKey);
        std::swap(to.nHeight, nHeight);
        std::swap(to.nVersion, nVersion);
    }

    // equality test
    friend bool operator==(const CCoins &a, const CCoins &b) {
         return a.userName == b.userName &&
                a.pubKey == b.pubKey &&
                a.nHeight == b.nHeight &&
                a.nVersion == b.nVersion;
    }
    friend bool operator!=(const CCoins &a, const CCoins &b) {
        return !(a == b);
    }

    bool IsCoinBase() const {
        return false;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const {
        unsigned int nSize = 0;
        // version
        nSize += ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion);
        nSize += ::GetSerializeSize(userName, nType, nVersion);
        nSize += ::GetSerializeSize(pubKey, nType, nVersion);
        nSize += ::GetSerializeSize(VARINT(nHeight), nType, nVersion);
        return nSize;
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const {
        // version
        ::Serialize(s, VARINT(this->nVersion), nType, nVersion);
        // header code
        ::Serialize(s, userName, nType, nVersion);
        ::Serialize(s, pubKey, nType, nVersion);
        // coinbase height
        ::Serialize(s, VARINT(nHeight), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) {
        // version
        ::Unserialize(s, VARINT(this->nVersion), nType, nVersion);
        // header code
        ::Unserialize(s, userName, nType, nVersion);
        ::Unserialize(s, pubKey, nType, nVersion);
        // coinbase height
        ::Unserialize(s, VARINT(nHeight), nType, nVersion);
        Cleanup();
    }

    /*
    // mark an outpoint spent, and construct undo information
    bool Spend(const COutPoint &out, CTxInUndo &undo);

    // mark a vout spent
    bool Spend(int nPos);

    // check whether a particular output is still available
    bool IsAvailable(unsigned int nPos) const {
        return false;
    }
    */

    // check whether the entire CCoins is spent
    // note that only !IsPruned() CCoins can be serialized
    bool IsPruned() const {
        return false;
    }
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const int CURRENT_VERSION=2;
    int nVersion;
    int nHeight;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nHeight);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        nHeight = 0;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    )

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    uint256 GetPoWHash() const
    {
        uint256 thash;
        scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
        return thash;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.nHeight        = nHeight;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 BuildMerkleTree() const;

    const uint256 &GetTxHash(unsigned int nIndex) const {
        assert(vMerkleTree.size() > 0); // BuildMerkleTree must have been called first
        assert(nIndex < vtx.size());
        return vMerkleTree[nIndex];
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    void print() const;
};

#endif
