// Copyright (c) 2014 Miguel Freitas

#ifndef SOFT_CHECKPOINT_H
#define SOFT_CHECKPOINT_H

#define SOFT_CHECKPOINT_PERIOD 6

#include "serialize.h"
#include "net.h"
#include "uint256.h"

#include <vector>

class CSoftCheckpoint;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace SoftCheckpoints
{
    extern bool fEnabled;

    // Returns true if block passes checkpoint checks
    bool CheckBlock(int nHeight, const uint256& hash);

    void NewBlockAccepted();

    // returns true if vote is to be restransmitted
    bool CastVoteSoftCheckpoint(int height, const uint256 &hash, const std::string &username, const std::string &sign);
    
    void RelayCP(const CSoftCheckpoint& cp, CNode* pfrom);
    
    void RelayLastCPToNode(CNode* pnode);
    
    bool GetLastCPVotes(int &height, uint256 &hash, std::set<std::string> &usernames);
}

class CSoftCheckpoint
{
public:
    int nHeight;
    uint256 blockHash;
    std::vector<char> vchUsername;
    std::vector<char> vchSign;

    CSoftCheckpoint()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(blockHash);
        READWRITE(vchUsername);
        READWRITE(vchSign);
    )

    void SetNull()
    {
        nHeight = 0;
        blockHash = uint256();
        vchUsername.clear();
        vchSign.clear();
    }

    bool IsNull() const
    {
        return !nHeight;
    }
};


#endif
