// Copyright (c) 2014 Miguel Freitas

#ifndef DHTPROXY_H
#define DHTPROXY_H

#include "serialize.h"
#include "net.h"
#include "uint256.h"

#include <vector>

// just a small set of declarations to avoid main.c depending on libtorrent headers
namespace libtorrent {
    class alert_manager;
    class big_number;
    typedef big_number sha1_hash;
    class alert;
}

class CDHTTarget;
class CDHTGetRequest;
class CDHTGetReply;
class CDHTPutRequest;

/** 
 *   DHTGet Sequence:
 *
 *            Client                       Server
 * 1)      dhtgetMapAdd
 * 2)      dhtgetStartRequest
 *                  => CDHTGetRequest =>
 * 3)                                      dhtgetRequestReceived(stopReq=False)
 * 4)                                      (dhtgetPeerReqAdd)
 * 5)                                      (ses->dht_getData)
 * 6.1)                                    dhtgetPeerReqReply (from ThreadSessionAlerts)
 * 6.2)               <= CDHTGetReply <=
 * 6.3)    dhtgetReplyReceived
 * 6.4)    (dhtgetMapPost)
 * [ ..item 6 repeats... ]
 * 7)     dhtgetMapRemove
 * 8)     dhtgetStopRequest
 *                 => CDHTGetRequest =>
 * 9)                                     dhtgetRequestReceived(stopReq=True)
 * 10)                                     (dhtgetPeerReqRemove)
 *
 **
 *   DHTPut Sequence:
 *
 *            Client                       Server
 * 1)      dhtputRequest
 *                  => CDHTPutRequest =>
 * 2)                                      dhtputRequestReceived
 * 3)                                      (ses->dht_putDataSigned)
 */
namespace DhtProxy
{
    extern bool fEnabled;

    // Register a listener for dhtget requests (client side)
    void dhtgetMapAdd(libtorrent::sha1_hash &ih, libtorrent::alert_manager *am);
    
    // Unregister the dhtget listener (client side)
    void dhtgetMapRemove(libtorrent::sha1_hash &ih, libtorrent::alert_manager *am);

    // Request a dhtget. Returns the list of node the request was sent to. (client side)
    vector<CNode*> dhtgetStartRequest(std::string const &username, std::string const &resource, bool multi);
    
    // Stop a dhtget request to the nodes listed. (client side)
    void dhtgetStopRequest(vector<CNode*> vNodesReq, std::string const &username, std::string const &resource, bool multi);

    // Handle a dhtget request received from TCP. send request to UDP. (server side)
    // return true if accepted.
    bool dhtgetRequestReceived(const CDHTGetRequest& req, CNode* pfrom);
    
    // Handle a dhtget reply received from UDP, send it to the peers that made the request. (server side)
    void dhtgetPeerReqReply(libtorrent::sha1_hash &ih, const libtorrent::alert *a);

    // Handle a dhtget reply received from TCP. Will call dhtgetMapPost as needed. (client side)
    // return true if accepted.
    bool dhtgetReplyReceived(const CDHTGetReply& reply, CNode* pfrom);
    
    // Request a dhtput.
    void dhtputRequest(std::string const &username, std::string const &resource, bool multi,
                       std::string const &str_p, std::string const &sig_p, std::string const &sig_user);

    // Handle a dhtput request received from TCP. send request to UDP. (server side)
    // return true if accepted.
    bool dhtputRequestReceived(const CDHTPutRequest& req, CNode* pfrom);
    
    vector<CNode*> getRandomDhtProxies(int *totalProxyNodes = NULL);
}

class CDHTTarget
{
public:
    std::vector<char> vchUsername;
    std::vector<char> vchResource;
    bool resTypeMulti;

    CDHTTarget()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchUsername);
        READWRITE(vchResource);
        READWRITE(resTypeMulti);
    )

    void SetNull()
    {
        vchUsername.clear();
        vchResource.clear();
        resTypeMulti = false;
    }
};

class CDHTGetRequest : public CDHTTarget
{
public:
    bool stopReq;

    CDHTGetRequest() : CDHTTarget()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        CDHTTarget* pthis = (CDHTTarget*)(this);
        READWRITE(*pthis);
        READWRITE(stopReq);
    )

    void SetNull()
    {
        stopReq = false;
    }
};

class CDHTGetReply
{
public:
    std::vector<char> vchTargetHash;
    std::vector<char> vchBencodedData;

    CDHTGetReply()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchTargetHash);
        READWRITE(vchBencodedData);
    )

    void SetNull()
    {
        vchTargetHash.clear();
        vchBencodedData.clear();
    }
};

class CDHTPutRequest : public CDHTTarget
{
public:
    std::vector<char> vchStr_p;
    std::vector<char> vchSig_p;
    std::vector<char> vchSig_user;

    CDHTPutRequest() : CDHTTarget()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        CDHTTarget* pthis = (CDHTTarget*)(this);
        READWRITE(*pthis);
        READWRITE(vchStr_p);
        READWRITE(vchSig_p);
        READWRITE(vchSig_user);
    )

    void SetNull()
    {
        vchStr_p.clear();
        vchSig_p.clear();
        vchSig_user.clear();
    }
};


#endif
