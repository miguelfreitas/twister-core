// Copyright (c) 2014 Miguel Freitas
// tunnel DHT requests into tcp connection
// see: https://groups.google.com/forum/#!topic/twister-dev/uKjFGSw24yA

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/assign.hpp>
#include <boost/foreach.hpp>
#include <algorithm>    // std::random_shuffle

#include "dhtproxy.h"

#include "libtorrent/alert_manager.hpp"
#include "libtorrent/alert_types.hpp"
#include "libtorrent/peer_id.hpp"
#include "libtorrent/bencode.hpp"

#include "main.h"
#include "uint256.h"
#include "script.h"
#include "init.h"
#include "twister.h"
#include "twister_utils.h"

//#define dbgprintf OutputDebugStringF
#define dbgprintf(...) // no debug printf

using namespace libtorrent;

namespace DhtProxy
{
    bool fEnabled = true;
    CCriticalSection cs_dhtProxy;
    map<sha1_hash, std::list<alert_manager*> > m_dhtgetMap;
    map<sha1_hash, std::list<CService> > m_dhtgetPeersReq;

    class PeerBanStats {
      public:
        PeerBanStats() : active(0), count(0), limit(time_now()) {}
        int active;
        int count;
        ptime limit;
    };
    map<CService, PeerBanStats> m_peerBanStats;
    size_t numProxiesToUse = 4;
    
    void dhtgetMapAdd(sha1_hash &ih, alert_manager *am)
    {
        LOCK(cs_dhtProxy);
        m_dhtgetMap[ih].push_back(am);
    }
    
    void dhtgetMapRemove(sha1_hash &ih, alert_manager *am)
    {
        LOCK(cs_dhtProxy);
        std::map<sha1_hash, std::list<alert_manager*> >::iterator mi = m_dhtgetMap.find(ih);
        if( mi != m_dhtgetMap.end() ) {
            std::list<alert_manager *> &amList = (*mi).second;
            amList.remove(am);
            if( !amList.size() ) {
                m_dhtgetMap.erase(ih);
            }
        }
    }
    
    void dhtgetMapPost(sha1_hash &ih, const alert &a)
    {
        LOCK(cs_dhtProxy);
        std::map<sha1_hash, std::list<alert_manager*> >::iterator mi = m_dhtgetMap.find(ih);
        if( mi != m_dhtgetMap.end() ) {
            std::list<alert_manager *> &amList = (*mi).second;
            BOOST_FOREACH(alert_manager *am, amList) {
                am->post_alert(a);
            }
        }
    }
    
    vector<CNode*> getRandomDhtProxies(int *totalProxyNodes)
    {
        // (cs_vNodes) lock must be held!
        vector<CNode*> vNodesProxy;
        BOOST_FOREACH(CNode* pnode, vNodes) {
            if (pnode->nVersion >= DHT_PROXY_VERSION && !pnode->fNoDhtProxy) {
                vNodesProxy.push_back(pnode);
            }
        }
        if( totalProxyNodes ) 
            *totalProxyNodes = (int) vNodesProxy.size();
        std::random_shuffle(vNodesProxy.begin(),vNodesProxy.end());
        if(vNodesProxy.size() > numProxiesToUse) {
            vNodesProxy.resize(numProxiesToUse);
        }
        
        return vNodesProxy;
    }

    vector<CNode*> dhtgetStartRequest(std::string const &username, std::string const &resource, bool multi)
    {
        CDHTGetRequest req;
        req.vchUsername = std::vector<char>(username.begin(), username.end());
        req.vchResource = std::vector<char>(resource.begin(), resource.end());
        req.resTypeMulti = multi;
        req.stopReq = false;
    
        LOCK(cs_vNodes);
        vector<CNode*> vNodesReq = getRandomDhtProxies();
        BOOST_FOREACH(CNode* pnode, vNodesReq) {
            dbgprintf("DhtProxy::dhtgetStartRequest: pushMessage to %s\n", pnode->addr.ToString().c_str());
            pnode->PushMessage("dhtgetreq", req);
            pnode->AddRef();
        }
        if( !vNodesReq.size() ) {
            dbgprintf("DhtProxy::dhtgetStartRequest: sorry, no dht proxy found.\n");
            
            // fake no data to wakeup listener
            dht_reply_data_done_alert dd("","",false,false,false);
            sha1_hash ih = dhtTargetHash(username, resource, multi ? "m" : "s");
            dhtgetMapPost(ih, dd);
        }
        return vNodesReq;
    }

    void dhtgetStopRequest(vector<CNode*> vNodesReq, std::string const &username, std::string const &resource, bool multi)
    {   
        CDHTGetRequest req;
        req.vchUsername = std::vector<char>(username.begin(), username.end());
        req.vchResource = std::vector<char>(resource.begin(), resource.end());
        req.resTypeMulti = multi;
        req.stopReq = true;
        
        BOOST_FOREACH(CNode* pnode, vNodesReq) {
            dbgprintf("DhtProxy::dhtgetStopRequest: pushMessage to %s\n", pnode->addr.ToString().c_str());
            pnode->PushMessage("dhtgetreq", req);
            pnode->Release();
        }
    }
    
    void dhtgetPeerReqAdd(sha1_hash &ih, const CNode *pnode)
    {
        LOCK(cs_dhtProxy);
        m_dhtgetPeersReq[ih].push_back(pnode->addr);
        m_peerBanStats[pnode->addr].active++;
    }
    
    void dhtgetPeerReqRemove(sha1_hash &ih, const CNode *pnode)
    {
        LOCK(cs_dhtProxy);
        std::map<sha1_hash, std::list<CService> >::iterator mi = m_dhtgetPeersReq.find(ih);
        if( mi != m_dhtgetPeersReq.end() ) {
            std::list<CService> &addrList = (*mi).second;
            addrList.remove(pnode->addr);
            if( !addrList.size() ) {
                m_dhtgetPeersReq.erase(ih);
            }
            m_peerBanStats[pnode->addr].active--;
        }
    }
    
    void dhtgetPeerReqReply(sha1_hash &ih, const alert *a)
    {
        CDHTGetReply reply;
        reply.vchTargetHash = std::vector<char>(ih.begin(), ih.end());
        dht_reply_data_alert const* rd = alert_cast<dht_reply_data_alert>(a);
        if (rd) {
            bencode(std::back_inserter(reply.vchBencodedData), rd->m_lst);
        }
    
        LOCK(cs_dhtProxy);
        std::map<sha1_hash, std::list<CService> >::iterator mi = m_dhtgetPeersReq.find(ih);
        if( mi != m_dhtgetPeersReq.end() ) {
            std::list<CService> &addrList = (*mi).second;
            BOOST_FOREACH(CService &addr, addrList) {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes) {
                    if ((CService)pnode->addr == addr) {
                        dbgprintf("DhtProxy::dhtgetPeerReqReply: pushMessage to %s\n", pnode->addr.ToString().c_str());
                        pnode->PushMessage("dhtgetreply", reply);
                    }
                }
            }
        }
    }
    
    bool checkForAbuse(CNode* pfrom, int cost)
    {
        LOCK(cs_dhtProxy);

        // logic inspired/copied from dht_tracker.cpp:incoming_packet
        ptime now = time_now();
        PeerBanStats *match = &m_peerBanStats[pfrom->addr];
        match->count+=cost;
        if( match->count >= 500 ) {
            if (now < match->limit) {
                if( match->count == 500 ) { // cost may break this 'if' but then we just dont log.
                    dbgprintf("DhtProxy::checkForAbuse: %s misbehaving, too much requests.\n", 
                               pfrom->addr.ToString().c_str());
                }
                match->limit = now + minutes(5);
                return true;
            }
            match->count = 0;
            match->limit = now + seconds(5);
        }
        if( match->active > 10 ) {
            dbgprintf("DhtProxy::checkForAbuse: %s misbehaving, max active requests reached.\n", 
                       pfrom->addr.ToString().c_str());
            return true;
        }
        return false;
    }

    bool dhtgetRequestReceived(const CDHTGetRequest& req, CNode* pfrom)
    {
        if( fEnabled ) {
            // we are using proxy ourselves, we can't be proxy to anyone else
            pfrom->PushMessage("nodhtproxy");
            return true;
        } else if( !req.stopReq && checkForAbuse(pfrom, 1) ) {
            return false;
        } else {
            std::string username(req.vchUsername.data(), req.vchUsername.size());
            std::string resource(req.vchResource.data(), req.vchResource.size());
            bool           multi(req.resTypeMulti);
            
            dbgprintf("DhtProxy::dhtgetRequestReceived: (%s,%s,%d,stop=%d) from %s\n", 
                      username.c_str(), resource.c_str(), multi, req.stopReq,
                      pfrom->addr.ToString().c_str());
            
            sha1_hash ih = dhtTargetHash(username, resource, multi ? "m" : "s");
            if( !req.stopReq ) {
                dhtgetPeerReqAdd(ih, pfrom);
                dhtGetData(username, resource, multi, false);
            } else {
                dhtgetPeerReqRemove(ih, pfrom);
            }
            return true;
        }
    }
    
    bool dhtgetReplyReceived(const CDHTGetReply& reply, CNode* pfrom)
    {
        std::string strTargetHash(reply.vchTargetHash.data(), reply.vchTargetHash.size());
        sha1_hash ih(strTargetHash);
        
        if( !reply.vchBencodedData.size() ) {
            dbgprintf("DhtProxy::dhtgetReplyReceived: empty data from %s\n", 
                      pfrom->addr.ToString().c_str());
                  
            // No reply - these fields are not used, we just want cast in twister.cpp:dhtget to fail
            dht_reply_data_done_alert dd("","",false,false,false);
            dhtgetMapPost(ih, dd);
        } else {
            lazy_entry v;
            int pos;
            libtorrent::error_code ec;
            if (lazy_bdecode(reply.vchBencodedData.data(), reply.vchBencodedData.data() + 
                             reply.vchBencodedData.size(), v, ec, &pos) == 0 && v.type() == lazy_entry::list_t ) {
                // check signatures as we append to a libtorrent::entry list
                entry::list_type values_list;
                for (int i = 0; i < v.list_size(); ++i)
                {
                    lazy_entry const* e = v.list_at(i);
                    if (e->type() != lazy_entry::dict_t) continue;

                    lazy_entry const* p = e->dict_find("p");
                    if( !p || p->type() != lazy_entry::dict_t ) continue;
                    
                    lazy_entry const* target = p->dict_find("target");
                    if( !target || target->type() != lazy_entry::dict_t ) continue;
                    
                    lazy_entry const* r = target->dict_find("r");
                    lazy_entry const* t = target->dict_find("t");
                    if( !r || r->type() != lazy_entry::string_t ) continue;
                    if( !t || t->type() != lazy_entry::string_t ) continue;
                    
                    if( r->string_value() == "tracker" && t->string_value() == "m" ) {
                        // tracker reply has no signature
                    } else {
                        lazy_entry const* sig_p = e->dict_find("sig_p");
                        lazy_entry const* sig_user = e->dict_find("sig_user");
                        if (!sig_p || !sig_user) continue;
                        if (sig_p->type() != lazy_entry::string_t) continue;
                        if (sig_user->type() != lazy_entry::string_t) continue;

                        std::pair<char const*, int> buf = p->data_section();
                        if (!verifySignature(std::string(buf.first,buf.second),
                                    sig_user->string_value(),
                                    sig_p->string_value())) {
                            dbgprintf("DhtProxy::dhtgetReplyReceived: verifySignature failed\n");
                            continue;
                        }
                    }

                    values_list.push_back(entry());
                    values_list.back() = *e;
                }
                
                dbgprintf("DhtProxy::dhtgetReplyReceived: %zd entries from %s\n", 
                           values_list.size(), pfrom->addr.ToString().c_str());
                dht_reply_data_alert rd(values_list);
                dhtgetMapPost(ih, rd);
            } else {
                dbgprintf("DhtProxy::dhtgetReplyReceived: parsing error (data from %s)\n", 
                           pfrom->addr.ToString().c_str());
                return false;
            }
        }
        return true;
    }


    void dhtputRequest(std::string const &username, std::string const &resource, bool multi,
                       std::string const &str_p, std::string const &sig_p, std::string const &sig_user)
    {
        CDHTPutRequest req;
        req.vchUsername = std::vector<char>(username.begin(), username.end());
        req.vchResource = std::vector<char>(resource.begin(), resource.end());
        req.resTypeMulti = multi;
        req.vchStr_p    = std::vector<char>(str_p.begin(), str_p.end());
        req.vchSig_p    = std::vector<char>(sig_p.begin(), sig_p.end());
        req.vchSig_user = std::vector<char>(sig_user.begin(), sig_user.end());
    
        LOCK(cs_vNodes);
        vector<CNode*> vNodesReq = getRandomDhtProxies();
        BOOST_FOREACH(CNode* pnode, vNodesReq) {
            dbgprintf("DhtProxy::dhtputRequest: pushMessage to %s\n", pnode->addr.ToString().c_str());
            pnode->PushMessage("dhtputreq", req);
        }
        if( !vNodesReq.size() ) {
            dbgprintf("DhtProxy::dhtputRequest: sorry, no dht proxy found.\n");
        }
    }

    bool dhtputRequestReceived(const CDHTPutRequest& req, CNode* pfrom)
    {
        if( fEnabled ) {
            // we are using proxy ourselves, we can't be proxy to anyone else
            pfrom->PushMessage("nodhtproxy");
            return true;
        } else if( checkForAbuse(pfrom, 10) ) {
            return false;
        } else {
            std::string username(req.vchUsername.data(), req.vchUsername.size());
            std::string resource(req.vchResource.data(), req.vchResource.size());
            bool           multi(req.resTypeMulti);
            
            dbgprintf("DhtProxy::dhtputRequestReceived: (%s,%s,%d) from %s\n", 
                      username.c_str(), resource.c_str(), multi,
                      pfrom->addr.ToString().c_str());

            lazy_entry v;
            int pos;
            libtorrent::error_code ec;
            if (lazy_bdecode(req.vchStr_p.data(), req.vchStr_p.data() + 
                             req.vchStr_p.size(), v, ec, &pos) == 0 ) {
                entry p;
                p = v;
                std::string sig_p(req.vchSig_p.data(), req.vchSig_p.size());
                std::string sig_user(req.vchSig_user.data(), req.vchSig_user.size());

                dhtPutDataSigned(username,resource,multi,p,sig_p,sig_user, false);
            } else {
                dbgprintf("DhtProxy::dhtputRequestReceived: parsing error (data from %s)\n", 
                           pfrom->addr.ToString().c_str());
                return false;
            }
            return true;
        }
    }

}
