// Copyright (c) 2014 Miguel Freitas
// TODO: write description for the soft checkpoint
// More info:
// https://groups.google.com/forum/#!topic/twister-dev/tH3HlVQ_wmo

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/assign.hpp>
#include <boost/foreach.hpp>

#include "softcheckpoint.h"

#include "main.h"
#include "checkpoints.h"
#include "uint256.h"
#include "script.h"
#include "init.h"
#include "twister.h"

//#define dbgprintf OutputDebugStringF
#define dbgprintf(...) // no debug printf

namespace SoftCheckpoints
{
    bool fEnabled = true;
    CCriticalSection cs_softCP;

    typedef std::pair<int, uint256> Checkpoint;            // height, hash
    typedef std::map<std::string, std::string> CPSigMap;   // user, sign
    typedef std::pair<std::string, std::string> CPSigPair; // user, sign

    static Checkpoint lastSoftCP;
    static CPSigMap lastSoftCPSigs;
    
    static std::map<Checkpoint, CPSigMap> nextCandidates;
    static std::map<Checkpoint, CPSigMap> uncheckedCandidates;

    static std::set<std::string> uniqueUsersList =
            boost::assign::list_of
            ("mf1")("mf1a")("mf2")("mf3")
            ("omgasm");
            
    static std::set<std::string> upcomingUsersList =
            boost::assign::list_of
            ("nobody")("mf2a")("lxoliva")("stman")("wrewolf");


    void SetSoftCPBestChain() {
        // requires cs_main and cs_softCP locked (in this order)
        if( !fEnabled )
            return;
        
        if( lastSoftCP.first && mapBlockIndex.count(lastSoftCP.second) &&
            !mapBlockIndex[lastSoftCP.second]->IsInMainChain() ) {
            dbgprintf("SoftCheckpoints::SetSoftCPBestChain: lastSoftCP %d not in main chain\n", lastSoftCP.first);
            
            // ? use !mapOrphanBlocks.count() ?
            
            CBlockIndex *pindex = mapBlockIndex[lastSoftCP.second];
            while( pindex && !pindex->IsInMainChain() ) {
                pindex = pindex->pprev;
            }
            
            if( !pindex ) {
                dbgprintf("SoftCheckpoints::SetSoftCPBestChain: lastSoftCP %d currently orphaned? strange.\n", lastSoftCP.first);
                return;
            }
            
            dbgprintf("SoftCheckpoints::SetSoftCPBestChain: trying SetBestChain with lastSoftCP %d\n", lastSoftCP.first);
            CValidationState state;
            if (!SetBestChain(state, mapBlockIndex[lastSoftCP.second])) {
                dbgprintf("SoftCheckpoints::lastSoftCPUpdated: SetBestChain failed\n");
            }
        }
    }

    void LastSoftCPUpdated() {
        //LOCK(cs_main); // FIXME: not needed if called from ProcessMessage. check. wrong mutex order is bad.
        SetSoftCPBestChain();
    }

    std::string CPtoString(Checkpoint &cp) {
        CScript cs = CScript() << cp.first << cp.second;
        return std::string((const char *)cs.data(), cs.size());
    }

    void NewBlockAccepted() {
        LOCK(cs_softCP);
        SetSoftCPBestChain();
        
        if( (nBestHeight % SOFT_CHECKPOINT_PERIOD) == 0 &&
            nBestHeight > Checkpoints::GetHighestCheckpoint() &&
            nBestHeight >= lastSoftCP.first + SOFT_CHECKPOINT_PERIOD &&
            !fImporting && !fReindex) {
            LOCK(pwalletMain->cs_wallet);
            BOOST_FOREACH(const PAIRTYPE(CKeyID, CKeyMetadata)& item, pwalletMain->mapKeyMetadata)
            {
                const std::string &username = item.second.username;
                if(uniqueUsersList.count(username) || upcomingUsersList.count(username)) {
                    int height = nBestHeight - SOFT_CHECKPOINT_PERIOD;
                    dbgprintf("SoftCheckpoints::NewBlockAccepted: user '%s' will vote for %d\n", 
                              username.c_str(), height);
                    
                    CBlockIndex* pblockindex = FindBlockByHeight(height);
                    assert( pblockindex );
                    
                    Checkpoint cpPair = std::make_pair(height, *pblockindex->phashBlock);
                    std::string dataToSign = CPtoString(cpPair);
                    
                    std::string sign = createSignature(dataToSign, username);
                    
                    if( sign.size() ) {
                        if( CastVoteSoftCheckpoint(height, *pblockindex->phashBlock, username, sign) ) {
                            dbgprintf("SoftCheckpoints::NewBlockAccepted: relaying our own vote\n");
                            CSoftCheckpoint cp;
                            cp.nHeight = height;
                            cp.blockHash = *pblockindex->phashBlock;
                            cp.vchUsername = std::vector<char>(username.begin(), username.end());
                            cp.vchSign = std::vector<char>(sign.begin(), sign.end());
                            SoftCheckpoints::RelayCP(cp, NULL);
                        } else {
                            dbgprintf("SoftCheckpoints::NewBlockAccepted: CastVoteSoftCheckpoint failed for our own vote!\n");
                        }
                    } else {
                        dbgprintf("SoftCheckpoints::NewBlockAccepted: createSignature failed for user '%s'\n",
                              username.c_str());
                    }
                    break;
                }
            }
        }
        
                
        if( uncheckedCandidates.size() && nBestHeight > Checkpoints::GetHighestCheckpoint() ) {
            // pending unchecked
            dbgprintf("SoftCheckpoints::NewBlockAccepted process %zd pending unchecked (not implemented)\n",
                      uncheckedCandidates.size());
            uncheckedCandidates.clear();
        }
    }
  
    bool CastVerifiedVote(Checkpoint &cp, const std::string &username, const std::string &sign) {
        if( cp.first == lastSoftCP.first ) {
            if( lastSoftCPSigs.count(username) ) {
                dbgprintf("SoftCheckpoints::CastVerifiedVote: '%s' already voted for lastSoftCP %d\n", username.c_str(), cp.first);
                return false;
            }
            if( cp != lastSoftCP ) {
                dbgprintf("SoftCheckpoints::CastVerifiedVote: '%s' voted for a different hash than lastSoftCP %d\n", username.c_str(), cp.first);
                return false;
            }
            dbgprintf("SoftCheckpoints::CastVerifiedVote: new vote for lastSoftCP %d by '%s'\n", cp.first, username.c_str());
            lastSoftCPSigs[username] = sign;
            return true;
        }
    
        if( nextCandidates.count(cp) && nextCandidates[cp].count(username) ) {
            dbgprintf("SoftCheckpoints::CastVerifiedVote: '%s' already voted for candidate %d\n", username.c_str(), cp.first);
            return false;
        }
        
        nextCandidates[cp][username] = sign;
        if( nextCandidates[cp].size() > uniqueUsersList.size() / 2) {
            dbgprintf("SoftCheckpoints::CastVerifiedVote: new soft checkpoint %d wins!\n", cp.first);
            lastSoftCP = cp;
            lastSoftCPSigs = nextCandidates[cp];
            nextCandidates.clear();
            LastSoftCPUpdated();
        }
        return true;
    }
    
    // returns true if vote is to be restransmitted
    bool CastVoteSoftCheckpoint(int height, const uint256 &hash, const std::string &username, const std::string &sign) {
        LOCK(cs_softCP);
        
        if( (height % SOFT_CHECKPOINT_PERIOD) != 0 ) {
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: height %d not multiple of SOFT_CHECKPOINT_PERIOD\n", height);
            return false;
        }
    
        int hardCheckPointHeight = Checkpoints::GetHighestCheckpoint();
        
        if( height < hardCheckPointHeight ) {
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: height %d < hard checkpoint %d\n", height, hardCheckPointHeight);
            return false;
        } 
        
        if( height < lastSoftCP.first ) {
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: height %d < soft checkpoint %d\n", height, lastSoftCP.first);
            return false;
        }
        
        if( !uniqueUsersList.count(username) && !upcomingUsersList.count(username) ) {
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: username '%s' not accepted\n", username.c_str());
            return false;
        }
        
        Checkpoint cp = std::make_pair(height, hash);
        
        if( nBestHeight < hardCheckPointHeight ) {
            // still downloading blocks, we can't check signatures yet
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: vote for %d by '%s' added to unchecked\n", height, username.c_str());
            uncheckedCandidates[cp][username] = sign;
            return false;
        }
        
        if( !verifySignature( CPtoString(cp), username, sign) ) {
            dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: invalid signature by '%s'\n", username.c_str());
            return false;
        }
        
        dbgprintf("SoftCheckpoints::CastVoteSoftCheckpoint: signature by '%s' verified for %d, casting vote\n", 
                  username.c_str(), height);
        return CastVerifiedVote( cp, username, sign );
    }
    
    bool CheckBlock(int nHeight, const uint256& hash) {
        LOCK(cs_softCP);
        if (!fEnabled)
            return true;

        if (!lastSoftCP.first || nHeight != lastSoftCP.first)
            return true;
        dbgprintf("SoftCheckpoints::CheckBlock: height %d isOk=%d\n", nHeight, hash == lastSoftCP.second);
        return hash == lastSoftCP.second;
    }

    void RelayCP(const CSoftCheckpoint& cp, CNode* pfrom) {
        LOCK(cs_vNodes);
        dbgprintf("SoftCheckpoints::RelayCP: relaying softCP height %d from %s\n", 
                  cp.nHeight, !pfrom ? "localhost" : pfrom->addr.ToString().c_str());
        BOOST_FOREACH(CNode* pnode, vNodes) {
            if(pnode == pfrom)
                continue;
            if (pnode->nVersion >= SOFT_CHECKPOINT_VERSION) {
                dbgprintf("SoftCheckpoints::RelayCP: pushMessage to %s\n", pnode->addr.ToString().c_str());
                pnode->PushMessage("cp", cp);
            }
        }
        
        if( pfrom && lastSoftCP.first == cp.nHeight ) {
            if( !mapBlockIndex.count(lastSoftCP.second) ) {
                dbgprintf("SoftCheckpoints::RelayCP: requesting block height %d from node\n", cp.nHeight);
                PushGetBlocks(pfrom, pindexBest, cp.blockHash);
            }
        }
    }

    void RelayLastCPToNode(CNode* pnode) {
        LOCK(cs_softCP);
        if (!lastSoftCP.first)
            return;

        if (pnode->nVersion >= SOFT_CHECKPOINT_VERSION) {
            dbgprintf("SoftCheckpoints::RelayToLastCP: relaying lastSoftCP height %d (size %zd) to %s\n", 
                      lastSoftCP.first, lastSoftCPSigs.size(), pnode->addr.ToString().c_str());

            BOOST_FOREACH(const CPSigMap::value_type& i, lastSoftCPSigs) {
                CSoftCheckpoint cp;
                
                cp.nHeight = lastSoftCP.first;
                cp.blockHash = lastSoftCP.second;
                cp.vchUsername = std::vector<char>(i.first.begin(), i.first.end());
                cp.vchSign = std::vector<char>(i.second.begin(), i.second.end());
                pnode->PushMessage("cp", cp);
            }
        }
    }

    bool GetLastCPVotes(int &height, uint256 &hash, std::set<std::string> &usernames) {
        LOCK(cs_softCP);
        if (!lastSoftCP.first)
            return false;
        
        height = lastSoftCP.first;
        hash = lastSoftCP.second;

        usernames.clear();
        BOOST_FOREACH(const CPSigMap::value_type& i, lastSoftCPSigs) {
                usernames.insert(i.first);
        }
        return true;
    }
}
