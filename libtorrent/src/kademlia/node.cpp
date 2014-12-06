/*

Copyright (c) 2006-2012, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "libtorrent/pch.hpp"

#include <utility>
#include <boost/bind.hpp>
#include <boost/function/function1.hpp>
//#include <boost/date_time/posix_time/time_formatters_limited.hpp>
#include <boost/random.hpp>
#include <boost/nondet_random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/foreach.hpp>

#include "libtorrent/io.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/hasher.hpp"
#include "libtorrent/alert_types.hpp"
#include "libtorrent/alert.hpp"
#include "libtorrent/socket.hpp"
#include "libtorrent/random.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/kademlia/node_id.hpp"
#include "libtorrent/kademlia/rpc_manager.hpp"
#include "libtorrent/kademlia/routing_table.hpp"
#include "libtorrent/kademlia/node.hpp"

#include "libtorrent/kademlia/refresh.hpp"
#include "libtorrent/kademlia/find_data.hpp"
#include "libtorrent/kademlia/dht_get.hpp"
#include "libtorrent/rsa.hpp"

#include "../../src/twister.h"

/* refresh dht itens we know by putting them to other peers every 60 minutes.
 * this period must be small enough to ensure persistency and big enough to
 * not cause too much wasteful network traffic / overhead.
 * see http://conferences.sigcomm.org/imc/2007/papers/imc150.pdf for a good
 * discussion about that (quote: "These results suggest that periodic
 * insertions can be performed at the granularity of hours with little impact
 * on data persistence.")
 *
 * locally generated items are considered "unconfirmed" and have a smaller
 * refresh period (1 minute) until we read them back from other nodes.
 */
#define DHT_REFRESH_CONFIRMED minutes(60)
#define DHT_REFRESH_UNCONFIRMED minutes(1)

namespace libtorrent { namespace dht
{

void incoming_error(entry& e, char const* msg);

using detail::write_endpoint;

// TODO: 2 make this configurable in dht_settings
enum { announce_interval = 30 };

#ifdef TORRENT_DHT_VERBOSE_LOGGING
TORRENT_DEFINE_LOG(node)

extern int g_failed_announces;
extern int g_announces;

#endif

// remove peers that have timed out
void purge_peers(std::set<peer_entry>& peers)
{
	for (std::set<peer_entry>::iterator i = peers.begin()
		  , end(peers.end()); i != end;)
	{
		// the peer has timed out
		if (i->added + minutes(int(announce_interval * 1.5f)) < time_now())
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			TORRENT_LOG(node) << "peer timed out at: " << i->addr;
#endif
			peers.erase(i++);
		}
		else
			++i;
	}
}

void nop() {}

node_impl::node_impl(alert_dispatcher* alert_disp
	, udp_socket_interface* sock
	, dht_settings const& settings, node_id nid, address const& external_address
	, dht_observer* observer)
	: m_settings(settings)
	, m_id(nid == (node_id::min)() || !verify_id(nid, external_address) ? generate_id(external_address) : nid)
	, m_table(m_id, 8, settings)
	, m_rpc(m_id, m_table, sock, observer)
	, m_storage_table()
	, m_posts_by_user()
	, m_last_tracker_tick(time_now())
	, m_next_storage_refresh(time_now())
	, m_post_alert(alert_disp)
	, m_sock(sock)
{
	m_secret[0] = random();
	m_secret[1] = std::rand();
}

bool node_impl::verify_token(std::string const& token, char const* info_hash
	, udp::endpoint const& addr)
{
	if (token.length() != 4)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(node) << "token of incorrect length: " << token.length();
#endif
		return false;
	}

	hasher h1;
	error_code ec;
	std::string address = addr.address().to_string(ec);
	if (ec) return false;
	h1.update(&address[0], address.length());
	h1.update((char*)&m_secret[0], sizeof(m_secret[0]));
	h1.update((char*)info_hash, sha1_hash::size);
	
	sha1_hash h = h1.final();
	if (std::equal(token.begin(), token.end(), (char*)&h[0]))
		return true;
		
	hasher h2;
	h2.update(&address[0], address.length());
	h2.update((char*)&m_secret[1], sizeof(m_secret[1]));
	h2.update((char*)info_hash, sha1_hash::size);
	h = h2.final();
	if (std::equal(token.begin(), token.end(), (char*)&h[0]))
		return true;
	return false;
}

std::string node_impl::generate_token(udp::endpoint const& addr, char const* info_hash)
{
	std::string token;
	token.resize(4);
	hasher h;
	error_code ec;
	std::string address = addr.address().to_string(ec);
	TORRENT_ASSERT(!ec);
	h.update(&address[0], address.length());
	h.update((char*)&m_secret[0], sizeof(m_secret[0]));
	h.update(info_hash, sha1_hash::size);

	sha1_hash hash = h.final();
	std::copy(hash.begin(), hash.begin() + 4, (char*)&token[0]);
	TORRENT_ASSERT(std::equal(token.begin(), token.end(), (char*)&hash[0]));
	return token;
}

void node_impl::refresh(node_id const& id
	, find_data::nodes_callback const& f)
{
	boost::intrusive_ptr<dht::refresh> r(new dht::refresh(*this, id, f));
	r->start();
}

void node_impl::bootstrap(std::vector<udp::endpoint> const& nodes
	, find_data::nodes_callback const& f)
{
	boost::intrusive_ptr<dht::refresh> r(new dht::bootstrap(*this, m_id, f));

#ifdef TORRENT_DHT_VERBOSE_LOGGING
	int count = 0;
#endif

	for (std::vector<udp::endpoint>::const_iterator i = nodes.begin()
		, end(nodes.end()); i != end; ++i)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		++count;
#endif
		r->add_entry(node_id(0), *i, observer::flag_initial);
	}
	
#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_LOG(node) << "bootstrapping with " << count << " nodes";
#endif
	r->start();
}

int node_impl::bucket_size(int bucket)
{
	return m_table.bucket_size(bucket);
}

void node_impl::new_write_key()
{
	m_secret[1] = m_secret[0];
	m_secret[0] = random();
}

void node_impl::unreachable(udp::endpoint const& ep)
{
	m_rpc.unreachable(ep);
}

// new message received from network
void node_impl::incoming(msg const& m)
{
	// is this a reply?
	lazy_entry const* y_ent = m.message.dict_find_string("z");
	if (!y_ent || y_ent->string_length() == 0)
	{
		entry e;
		incoming_error(e, "missing 'z' entry");
		// [MF] silently ignore bad packet
		//m_sock->send_packet(e, m.addr, 0);
		return;
	}

	char y = *(y_ent->string_ptr());

	switch (y)
	{
		case 'r':
		{
			node_id id;
			// reply to our request?
			// map transaction => observer, call o->reply, ret true if ok
			if (m_rpc.incoming(m, &id))
				refresh(id, boost::bind(&nop));
			break;
		}
		case 'q':
		{
			// new request received
			TORRENT_ASSERT(m.message.dict_find_string_value("z") == "q");
			entry e;
			incoming_request(m, e);
			m_sock->send_packet(e, m.addr, 0);
			break;
		}
		case 'e':
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			lazy_entry const* err = m.message.dict_find_list("e");
			if (err && err->list_size() >= 2)
			{
				TORRENT_LOG(node) << "INCOMING ERROR: " << err->list_string_value_at(1);
			}
#endif
			lazy_entry const* err = m.message.dict_find_list("e");
			if (err && err->list_size() >= 2)
			{
				printf("INCOMING ERROR: %s\n", err->list_string_value_at(1).c_str());
			}
			break;
		}
	}
}

namespace
{
	void announce_fun(std::vector<std::pair<node_entry, std::string> > const& v
		, node_impl& node, int listen_port, sha1_hash const& ih, bool seed)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(node) << "sending announce_peer [ ih: " << ih
			<< " p: " << listen_port
			<< " nodes: " << v.size() << " ]" ;
#endif

		// create a dummy traversal_algorithm		
		boost::intrusive_ptr<traversal_algorithm> algo(
			new traversal_algorithm(node, (node_id::min)()));

		// store on the first k nodes
		for (std::vector<std::pair<node_entry, std::string> >::const_iterator i = v.begin()
			, end(v.end()); i != end; ++i)
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			TORRENT_LOG(node) << "  announce-distance: " << (160 - distance_exp(ih, i->first.id));
#endif

			void* ptr = node.m_rpc.allocate_observer();
			if (ptr == 0) return;
			observer_ptr o(new (ptr) announce_observer(algo, i->first.ep(), i->first.id));
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			o->m_in_constructor = false;
#endif
			entry e;
			e["z"] = "q";
			e["q"] = "announcePeer";
			entry& a = e["x"];
			a["infoHash"] = ih.to_string();
			a["port"] = listen_port;
			a["token"] = i->second;
			a["seed"] = int(seed);
			node.m_rpc.invoke(e, i->first.ep(), o);
		}
	}

	double getRandom()
	{
		static boost::mt19937 m_random_seed;
		static boost::uniform_real<double> m_random_dist(0.0, 1.0);
		static boost::variate_generator<boost::mt19937&, boost::uniform_real<double> > m_random(m_random_seed, m_random_dist);

		return m_random();
	}

	ptime getNextRefreshTime(bool confirmed = true)
	{
		static ptime nextRefreshTime[2] = { ptime(), ptime() };
		nextRefreshTime[confirmed] = std::max(
				nextRefreshTime[confirmed] + milliseconds(500),
				// add +/-10% diffusion to next refresh time
				time_now() + (confirmed ? DHT_REFRESH_CONFIRMED : DHT_REFRESH_UNCONFIRMED)
					   * ( 0.9 + 0.2 * getRandom() )
			);
		return nextRefreshTime[confirmed];
	}

	void putData_confirm(entry::list_type const& values_list, dht_storage_item& item)
	{
		if( !item.confirmed ) {
			BOOST_FOREACH(const entry &e, values_list) {
				entry const *sig_p = e.find_key("sig_p");
				if( sig_p && sig_p->type() == entry::string_t &&
				    sig_p->string() == item.sig_p ) {
					item.confirmed = true;
					break;
				}
			}
			if( !item.confirmed && time(NULL) > item.local_add_time + 60*60*24*2 ) {
				item.confirmed = true; // force confirm by timeout
			}
			if( item.confirmed ) {
				item.next_refresh_time = getNextRefreshTime();
			}
		}
	}

	void putData_fun(std::vector<std::pair<node_entry, std::string> > const& v,
			 node_impl& node,
             entry const &p, std::string const &sig_p, std::string const &sig_user)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(node) << "sending putData [ username: " << username
			<< " res: " << resource
			<< " nodes: " << v.size() << " ]" ;
#endif

		// create a dummy traversal_algorithm
		boost::intrusive_ptr<traversal_algorithm> algo(
			new traversal_algorithm(node, (node_id::min)()));

		// store on the first k nodes
		for (std::vector<std::pair<node_entry, std::string> >::const_iterator i = v.begin()
			, end(v.end()); i != end; ++i)
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			TORRENT_LOG(node) << "  putData-distance: " << (160 - distance_exp(ih, i->first.id));
#endif

			void* ptr = node.m_rpc.allocate_observer();
			if (ptr == 0) return;
			observer_ptr o(new (ptr) announce_observer(algo, i->first.ep(), i->first.id));
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			o->m_in_constructor = false;
#endif
			entry e;
			e["z"] = "q";
			e["q"] = "putData";
			entry& a = e["x"];
			a["token"] = i->second;

            a["p"] = p;
			a["sig_p"] = sig_p;
			a["sig_user"] = sig_user;

			node.m_rpc.invoke(e, i->first.ep(), o);
		}
	}

	void getDataDone_fun(std::vector<std::pair<node_entry, std::string> > const& node_results,
			     bool got_data, node_id target, node_impl& node,
			     boost::function<void(bool, bool)> fdone)
	{
	    bool is_neighbor = false;

	    // check distance between target, nodes and our own id
	    // n is sorted from closer(begin) to more distant (back)
	    if( node_results.size() < node.m_table.bucket_size() ) {
		    is_neighbor = true;
	    } else {
		    node_id dFarther = distance(node_results.back().first.id, target);
		    node_id dOwn     = distance(node.nid(), target);
		    if( dOwn < dFarther )
			    is_neighbor = true;
	    }

	    fdone(is_neighbor, got_data);
	}
}

void node_impl::add_router_node(udp::endpoint router)
{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_LOG(node) << "adding router node: " << router;
#endif
	m_table.add_router_node(router);
}

void node_impl::add_node(udp::endpoint node)
{
	// ping the node, and if we get a reply, it
	// will be added to the routing table
	void* ptr = m_rpc.allocate_observer();
	if (ptr == 0) return;

	// create a dummy traversal_algorithm		
	// this is unfortunately necessary for the observer
	// to free itself from the pool when it's being released
	boost::intrusive_ptr<traversal_algorithm> algo(
		new traversal_algorithm(*this, (node_id::min)()));
	observer_ptr o(new (ptr) null_observer(algo, node, node_id(0)));
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
	o->m_in_constructor = false;
#endif
	entry e;
	e["z"] = "q";
	e["q"] = "ping";
	m_rpc.invoke(e, node, o);
}

void node_impl::announce(std::string const& trackerName, sha1_hash const& info_hash, address addr, int listen_port, bool seed, bool myself, int list_peers
	, boost::function<void(std::vector<tcp::endpoint> const&)> f)
{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_LOG(node) << "announcing [ ih: " << info_hash << " p: " << listen_port << " ]" ;
#endif
	//printf("node_impl::announce '%s' host: %s:%d myself=%d\n", trackerName.c_str(), addr.to_string().c_str(), listen_port, myself);

	// [MF] is_unspecified() is not always available. never mind.
	//if( !addr.is_unspecified() ) {
		add_peer( trackerName, info_hash, addr, listen_port, seed, list_peers );
	//}

	// do not announce other peers, just add them to our local m_map.
	if( myself ) {
		// search for nodes with ids close to id or with peers
		// for info-hash id. then send announce_peer to them.
		boost::intrusive_ptr<find_data> ta(new find_data(*this, trackerName, info_hash, f
			, boost::bind(&announce_fun, _1, boost::ref(*this)
			, listen_port, info_hash, seed), seed));
		ta->start();
	}
}

void node_impl::putDataSigned(std::string const &username, std::string const &resource, bool multi,
             entry const &p, std::string const &sig_p, std::string const &sig_user, bool local)
{
    printf("putDataSigned: username=%s,res=%s,multi=%d sig_user=%s\n",
            username.c_str(), resource.c_str(), multi, sig_user.c_str());

    // consistency checks
    entry const* seqEntry = p.find_key("seq");
    entry const* heightEntry = p.find_key("height");
    entry const* target = p.find_key("target");
    std::string n, r, t;
    if( target ) {
        entry const* nEntry = target->find_key("n");
        entry const* rEntry = target->find_key("r");
        entry const* tEntry = target->find_key("t");
        if( nEntry && nEntry->type() == entry::string_t )
            n = nEntry->string();
        if( rEntry && rEntry->type() == entry::string_t )
            r = rEntry->string();
        if( tEntry && tEntry->type() == entry::string_t )
            t = tEntry->string();
    }
    if( p.find_key("v") && heightEntry && heightEntry->type() == entry::int_t &&
        (multi || (seqEntry && seqEntry->type() == entry::int_t)) && target &&
        n == username && r == resource && ((!multi && t == "s") || (multi && t == "m")) ) {

        // search for nodes with ids close to id or with peers
        // for info-hash id. then send putData to them.
        boost::intrusive_ptr<dht_get> ta(new dht_get(*this, username, resource, multi,
             boost::bind(&nop),
             boost::bind(&putData_fun, _1, boost::ref(*this), p, sig_p, sig_user), true, local));
    
        if( local ) {
            // store it locally so it will be automatically refreshed with the rest
            std::vector<char> pbuf;
            bencode(std::back_inserter(pbuf), p);
            std::string str_p = std::string(pbuf.data(),pbuf.size());
    
            dht_storage_item item(str_p, sig_p, sig_user);
            item.local_add_time = time(NULL);
            item.confirmed = false;
            std::vector<char> vbuf;
            bencode(std::back_inserter(vbuf), p["v"]);
            std::pair<char const*, int> bufv = std::make_pair(vbuf.data(), vbuf.size());
    
            int seq = (seqEntry && seqEntry->type() == entry::int_t) ? seqEntry->integer() : -1;
            int height = heightEntry->integer();
            if( store_dht_item(item, ta->target(), multi, seq, height, bufv) ) {
                // local items not yet processed for hashtags and post counts
                // not that bad - but we may eventually want to implement this
                //process_newly_stored_entry(p);
            }
        }
    
        // now send it to the network (start transversal algorithm)
        ta->start();
    } else {
        printf("putDataSigned: consistency checks failed!\n");
    }
}


void node_impl::getData(std::string const &username, std::string const &resource, bool multi,
			boost::function<void(entry::list_type const&)> fdata,
			boost::function<void(bool, bool)> fdone, bool local)
{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_LOG(node) << "getData [ username: " << info_hash << " res: " << resource << " ]" ;
#endif
	// search for nodes with ids close to id or with peers
	// for info-hash id. callback is used to return data.
	boost::intrusive_ptr<dht_get> ta(new dht_get(*this, username, resource, multi,
		 fdata,
		 boost::bind(&getDataDone_fun, _1, _2, _3, boost::ref(*this), fdone), false, local));
	ta->start();
}

void node_impl::tick()
{
	node_id target;
	if (m_table.need_refresh(target))
		refresh(target, boost::bind(&nop));

    ptime now = time_now();
    if (now > m_next_storage_refresh ) {
        refresh_storage();
    }
}

void node_impl::process_newly_stored_entry(const lazy_entry &p)
{
    const lazy_entry *target = p.dict_find_dict("target");
    if( !target )
        return;
    
    std::string username = target->dict_find_string_value("n");
    std::string resource = target->dict_find_string_value("r");
    bool multi = (target->dict_find_string_value("t") == "m");

    // update hashtags stats
    const lazy_entry *v = p.dict_find_dict("v");
    if( v && !multi ) {
        const lazy_entry *userpost = v->dict_find_dict("userpost");
        if( userpost ) {
            int64_t time = p.dict_find_int_value("time");
            const lazy_entry *rt = userpost->dict_find_dict("rt");
            std::string msg;
            if( rt ) {
                msg = rt->dict_find_string_value("msg");
            } else {
                msg = userpost->dict_find_string_value("msg");
            }
            if( msg.size() ) {
                updateSeenHashtags(msg,time);
            }
        }
    }
    
    // update posts stats
    std::string resourcePost("post");
    if( resource.compare(0, resourcePost.length(), resourcePost) == 0 ) {
        int resourceNumber = atoi( resource.c_str() + resourcePost.length() );
        std::pair<int,int> &userStats = m_posts_by_user[username];
        userStats.first++; //total
        userStats.second = std::max(userStats.second, resourceNumber);
    }
}

bool node_impl::refresh_storage() {
    bool did_something = false;

    ptime const now = time_now();
    m_next_storage_refresh = now + DHT_REFRESH_CONFIRMED;

    for (dht_storage_table_t::iterator i = m_storage_table.begin(),
         end(m_storage_table.end()); i != end; ++i )
    {
        dht_storage_list_t& lsto = i->second;
        dht_storage_list_t::iterator j(lsto.begin()), jEnd(lsto.end());
        for(int jIdx = 0; j != jEnd; ++j, ++jIdx ) {
            dht_storage_item& item = *j;

            if( has_expired(item, true) ) {
                continue;
            }

            if( item.next_refresh_time > now ) {
                // this item won't be refreshed this time,
                // but it may shorten sleep time to next refresh
                if( m_next_storage_refresh > item.next_refresh_time ) {
                    m_next_storage_refresh = item.next_refresh_time;
                }
                continue;
            }

            bool skip = false;
            bool local_and_recent = (item.local_add_time && item.local_add_time + 60*60*24*2 > time(NULL));
            
            lazy_entry p;
            int pos;
            error_code err;
            // FIXME: optimize to avoid bdecode (store seq separated, etc)
            int ret = lazy_bdecode(item.p.data(), item.p.data() + item.p.size(), p, err, &pos, 10, 500);

            int height = p.dict_find_int_value("height");
            if( height > getBestHeight() ) {
                skip = true;  // invalid? how come?
            }

            const lazy_entry *target = p.dict_find_dict("target");
            if( !target )
                continue;
            std::string username = target->dict_find_string_value("n");
            std::string resource = target->dict_find_string_value("r");
            bool multi = (target->dict_find_string_value("t") == "m");

            // probabilistic refresh for users that post a lot.
            // note: we don't know the true total number of posts by user, but
            //       rather just what we have stored and still not expired.
            std::string resourcePost("post");
            if( resource.compare(0, resourcePost.length(), resourcePost) == 0 ) {
                int resourceNumber = atoi( resource.c_str() + resourcePost.length() );
                std::pair<int,int> &userStats = m_posts_by_user[username];
                int knownPosts = userStats.first;
                int lastPost = userStats.second;
#ifdef TORRENT_DHT_VERBOSE_LOGGING
                printf("node dht: probabilistic post refresh for user: %s (total: %d last: %d cur: %d)\n", 
                       username.c_str(), knownPosts, lastPost, resourceNumber);
#endif
                if( resourceNumber < lastPost - 100 && knownPosts > 25 ) {
                    double p = 25. / (knownPosts - 25);
                    if( getRandom() > p ) {
                        skip = true;
                    }
                }
            }

            // refresh only signed single posts and mentions
            if( !skip &&
                (!multi || resource == "mention" || local_and_recent) ) {
#ifdef TORRENT_DHT_VERBOSE_LOGGING
                    printf("node dht: refreshing storage: [%s,%s,%s]\n",
                           username.c_str(),
                           resource.c_str(),
                           target->dict_find_string_value("t").c_str());
#endif
                entry entryP;
                entryP = p; // lazy to non-lazy

                // search for nodes with ids close to id or with peers
                // for info-hash id. then send putData to them.
                boost::intrusive_ptr<dht_get> ta(new dht_get(*this, username, resource, multi,
                                                             boost::bind(&putData_confirm, _1, boost::ref(item)),
                                                             boost::bind(&putData_fun, _1, boost::ref(*this),
                                                                         entryP, item.sig_p, item.sig_user),
                                                             item.confirmed,
                                                             item.local_add_time));
                ta->start();
                did_something = true;
            }

            // we are supposed to have refreshed this item by now (but we may have not - see above)
            // so regardless of what we actually did, calculate when the next refresh is due
            item.next_refresh_time = getNextRefreshTime(item.confirmed);
            if( m_next_storage_refresh > item.next_refresh_time ) {
                m_next_storage_refresh = item.next_refresh_time;
            }
        }
    }
/*
    printf("node dht: next storage refresh in %d\n",
           m_next_storage_refresh - now );
*/
    return did_something;
}

bool node_impl::has_expired(dht_storage_item const& item, bool skipSigCheck) {
    // dont expire if block chain is invalid
    if( getBestHeight() < 1 )
        return false;

    if (!skipSigCheck && !verifySignature(item.p, item.sig_user, item.sig_p)) {
        // invalid signature counts as expired
        printf("node_impl::has_expired verifySignature failed\n");
        return true;
    }

    lazy_entry arg_ent;
    int pos;
    error_code err;
    // FIXME: optimize to avoid bdecode (store seq separated, etc)
    int ret = lazy_bdecode(item.p.data(), item.p.data() + item.p.size(), arg_ent, err, &pos, 10, 500);

    const static key_desc_t msg_desc[] = {
        {"v", lazy_entry::none_t, 0, 0},
        {"seq", lazy_entry::int_t, 0, key_desc_t::optional},
        {"time", lazy_entry::int_t, 0, 0},
        {"height", lazy_entry::int_t, 0, 0},
        {"target", lazy_entry::dict_t, 0, key_desc_t::parse_children},
        {"n", lazy_entry::string_t, 0, 0},
        {"r", lazy_entry::string_t, 0, 0},
        {"t", lazy_entry::string_t, 0, 0},
    };
    enum {mk_v = 0, mk_seq, mk_time, mk_height,
          mk_target, mk_n, mk_r, mk_t};

    // attempt to parse the message
    lazy_entry const* msg_keys[8];
    char error_string[200];
    if (!verify_message(&arg_ent, msg_desc, msg_keys, 8, error_string, sizeof(error_string)))
    {
        printf("node_impl::has_expired verify_message failed\n");
        // parse error (how come?) counts as expired
        return true;
    }

    bool multi = (msg_keys[mk_t]->string_value() == "m");
    int height = msg_keys[mk_height]->int_value();
    std::string resource = msg_keys[mk_r]->string_value();

    return shouldDhtResourceExpire(resource, multi, height);
}

bool node_impl::save_storage(entry &save) const {
    bool did_something = false;

    if( m_storage_table.size() == 0 )
        return did_something;

    printf("node dht: saving storage... (storage_table.size = %lu)\n", m_storage_table.size());

    for (dht_storage_table_t::const_iterator i = m_storage_table.begin(),
         iend(m_storage_table.end()); i != iend; ++i )
    {
        entry save_list(entry::list_t);

        dht_storage_list_t const& lsto = i->second;
        // save only 's' items? for now save everything
        /*if( lsto.size() == 1 )*/ {
            for(dht_storage_list_t::const_iterator j = lsto.begin(),
                jend(lsto.end()); j != jend; ++j ) {

                dht_storage_item const& item = *j;

                entry entry_item;
                entry_item["p"] = item.p;
                entry_item["sig_p"] = item.sig_p;
                entry_item["sig_user"] = item.sig_user;
                if( item.local_add_time )
                    entry_item["local_add_time"] = item.local_add_time;
                entry_item["confirmed"] = item.confirmed ? 1 : 0;
                save_list.list().push_back(entry_item);
            }
        }

        if( save_list.list().size() ) {
            save[i->first.to_string()] = save_list;
            did_something = true;
        }
    }
    return did_something;
}

void node_impl::load_storage(entry const* e) {
    if( !e || e->type() != entry::dictionary_t)
        return;

    ptime const now = time_now();
    time_duration const refresh_interval = std::max( DHT_REFRESH_CONFIRMED, milliseconds(e->dict().size() * 500) );

    printf("node dht: loading storage... (%lu node_id keys)\n", e->dict().size());

    for (entry::dictionary_type::const_iterator i = e->dict().begin();
         i != e->dict().end(); ++i) {

        node_id target( i->first );
        dht_storage_list_t to_add;
        if ( i->second.type() != entry::list_t )
            continue;
        for (entry::list_type::const_iterator j = i->second.list().begin();
             j != i->second.list().end(); ++j) {
            dht_storage_item item;
            item.p = j->find_key("p")->string();
            item.sig_p = j->find_key("sig_p")->string();
            item.sig_user = j->find_key("sig_user")->string();
            entry const *local_add_time( j->find_key("local_add_time") );
            if(local_add_time)
                item.local_add_time = local_add_time->integer();
            entry const *confirmed( j->find_key("confirmed") );
            if(confirmed) {
                item.confirmed = (confirmed->integer() != 0);
            }

            bool expired = has_expired(item);
            if( !expired ) {
                lazy_entry p;
                int pos;
                error_code err;
                // FIXME: optimize to avoid bdecode (store seq separated, etc)
                int ret = lazy_bdecode(item.p.data(), item.p.data() + item.p.size(), p, err, &pos, 10, 500);
                process_newly_stored_entry(p);

                // wait 1 minute (to load torrents, etc.)
                // randomize refresh time
                item.next_refresh_time = now + minutes(1) + refresh_interval * getRandom();

                to_add.push_back(item);
            }
        }
        m_storage_table.insert(std::make_pair(target, to_add));
    }
}



time_duration node_impl::connection_timeout()
{
	time_duration d = m_rpc.tick();
	ptime now(time_now());
	if (now - m_last_tracker_tick < minutes(2)) return d;
	m_last_tracker_tick = now;

	/*
	for (dht_immutable_table_t::iterator i = m_immutable_table.begin();
		i != m_immutable_table.end();)
	{
		if (i->second.last_seen + minutes(60) > now)
		{
			++i;
			continue;
		}
		free(i->second.value);
		m_immutable_table.erase(i++);
	}
	*/

	// look through all peers and see if any have timed out
	for (table_t::iterator i = m_map.begin(), end(m_map.end()); i != end;)
	{
		torrent_entry& t = i->second;
		node_id const& key = i->first;
		++i;
		purge_peers(t.peers);

		// if there are no more peers, remove the entry altogether
		if (t.peers.empty())
		{
			table_t::iterator i = m_map.find(key);
			if (i != m_map.end()) m_map.erase(i);
		}
	}

	return d;
}

void node_impl::status(session_status& s)
{
	mutex_t::scoped_lock l(m_mutex);

	m_table.status(s);
	s.dht_torrents = int(m_map.size());
	s.active_requests.clear();
	s.dht_total_allocations = m_rpc.num_allocated_observers();
	for (std::set<traversal_algorithm*>::iterator i = m_running_requests.begin()
		, end(m_running_requests.end()); i != end; ++i)
	{
		s.active_requests.push_back(dht_lookup());
		dht_lookup& l = s.active_requests.back();
		(*i)->status(l);
	}
}

void node_impl::lookup_peers(sha1_hash const& info_hash, int prefix, entry& reply
	, bool noseed, bool scrape) const
{
	if (m_post_alert)
	{
		alert* a = new dht_get_peers_alert(info_hash);
		if (!m_post_alert->post_alert(a)) delete a;
	}

	table_t::const_iterator i = m_map.lower_bound(info_hash);
	if (i == m_map.end()) return;
	if (i->first != info_hash && prefix == 20) return;
	if (prefix != 20)
	{
		sha1_hash mask = sha1_hash::max();
		mask <<= (20 - prefix) * 8;
		if ((i->first & mask) != (info_hash & mask)) return;
	}

	torrent_entry const& v = i->second;

	if (!v.name.empty()) reply["n"] = v.name;
	reply["followers"] = v.list_peers;

	if (scrape)
	{
		bloom_filter<256> downloaders;
		bloom_filter<256> seeds;

		for (std::set<peer_entry>::const_iterator i = v.peers.begin()
			, end(v.peers.end()); i != end; ++i)
		{
			sha1_hash iphash;
			hash_address(i->addr.address(), iphash);
			if (i->seed) seeds.set(iphash);
			else downloaders.set(iphash);
		}

		reply["BFpe"] = downloaders.to_string();
		reply["BFse"] = seeds.to_string();
	}
	else
	{
		int num = (std::min)((int)v.peers.size(), m_settings.max_peers_reply);
		std::set<peer_entry>::const_iterator iter = v.peers.begin();
		entry::list_type& pe = reply["values"].list();
		std::string endpoint;

		for (int t = 0, m = 0; m < num && iter != v.peers.end(); ++iter, ++t)
		{
			if ((random() / float(UINT_MAX + 1.f)) * (num - t) >= num - m) continue;
			if (noseed && iter->seed) continue;
			endpoint.resize(18);
			std::string::iterator out = endpoint.begin();
			write_endpoint(iter->addr, out);
			endpoint.resize(out - endpoint.begin());
			pe.push_back(entry(endpoint));

			++m;
		}
	}
	return;
}

void node_impl::add_peer(std::string const &name, sha1_hash const& info_hash, address addr, int port, bool seed, int list_peers)
{
	torrent_entry& v = m_map[info_hash];

	// the peer announces a torrent name, and we don't have a name
	// for this torrent. Store it.
	if (name.size() && v.name.empty())
	{
		v.name = name;
		if (v.name.size() > 50) v.name.resize(50);
	}
	if (list_peers) v.list_peers = list_peers;

	peer_entry peer;
	peer.addr = tcp::endpoint(addr, port);
	peer.added = time_now();
	peer.seed = seed;
	std::set<peer_entry>::iterator i = v.peers.find(peer);
	if (i != v.peers.end()) v.peers.erase(i++);
	v.peers.insert(i, peer);
}

namespace
{
	void write_nodes_entry(entry& r, nodes_t const& nodes)
	{
		bool ipv6_nodes = false;
		entry& n = r["nodes"];
		std::back_insert_iterator<std::string> out(n.string());
		for (nodes_t::const_iterator i = nodes.begin()
			, end(nodes.end()); i != end; ++i)
		{
			if (!i->addr().is_v4())
			{
				ipv6_nodes = true;
				continue;
			}
			std::copy(i->id.begin(), i->id.end(), out);
			write_endpoint(udp::endpoint(i->addr(), i->port()), out);
		}

		if (ipv6_nodes)
		{
			entry& p = r["nodes2"];
			std::string endpoint;
			for (nodes_t::const_iterator i = nodes.begin()
				, end(nodes.end()); i != end; ++i)
			{
				if (!i->addr().is_v6()) continue;
				endpoint.resize(18 + 20);
				std::string::iterator out = endpoint.begin();
				std::copy(i->id.begin(), i->id.end(), out);
				out += 20;
				write_endpoint(udp::endpoint(i->addr(), i->port()), out);
				endpoint.resize(out - endpoint.begin());
				p.list().push_back(entry(endpoint));
			}
		}
	}
}

// verifies that a message has all the required
// entries and returns them in ret
bool verify_message(lazy_entry const* msg, key_desc_t const desc[], lazy_entry const* ret[]
	, int size , char* error, int error_size)
{
	// clear the return buffer
	memset(ret, 0, sizeof(ret[0]) * size);

	// when parsing child nodes, this is the stack
	// of lazy_entry pointers to return to
	lazy_entry const* stack[5];
	int stack_ptr = -1;

	if (msg->type() != lazy_entry::dict_t)
	{
		snprintf(error, error_size, "not a dictionary");
		return false;
	}
	++stack_ptr;
	stack[stack_ptr] = msg;
	for (int i = 0; i < size; ++i)
	{
		key_desc_t const& k = desc[i];

//		fprintf(stderr, "looking for %s in %s\n", k.name, print_entry(*msg).c_str());

		ret[i] = msg->dict_find(k.name);
		// none_t means any type
		if (ret[i] && ret[i]->type() != k.type && k.type != lazy_entry::none_t) ret[i] = 0;
		if (ret[i] == 0 && (k.flags & key_desc_t::optional) == 0)
		{
			// the key was not found, and it's not an optional key
			snprintf(error, error_size, "missing '%s' key", k.name);
			return false;
		}

		if (k.size > 0
			&& ret[i]
			&& k.type == lazy_entry::string_t)
		{
			bool invalid = false;
			if (k.flags & key_desc_t::size_divisible)
				invalid = (ret[i]->string_length() % k.size) != 0;
			else
				invalid = ret[i]->string_length() != k.size;

			if (invalid)
			{
				// the string was not of the required size
				ret[i] = 0;
				if ((k.flags & key_desc_t::optional) == 0)
				{
					snprintf(error, error_size, "invalid value for '%s'", k.name);
					return false;
				}
			}
		}
		if (k.flags & key_desc_t::parse_children)
		{
			TORRENT_ASSERT(k.type == lazy_entry::dict_t);

			if (ret[i])
			{
				++stack_ptr;
				TORRENT_ASSERT(stack_ptr < int(sizeof(stack)/sizeof(stack[0])));
				msg = ret[i];
				stack[stack_ptr] = msg;
			}
			else
			{
				// skip all children
				while (i < size && (desc[i].flags & key_desc_t::last_child) == 0) ++i;
				// if this assert is hit, desc is incorrect
				TORRENT_ASSERT(i < size);
			}
		}
		else if (k.flags & key_desc_t::last_child)
		{
			TORRENT_ASSERT(stack_ptr > 0);
			// this can happen if the specification passed
			// in is unbalanced. i.e. contain more last_child
			// nodes than parse_children
			if (stack_ptr == 0) return false;
			--stack_ptr;
			msg = stack[stack_ptr];
		}
	}
	return true;
}

void incoming_error(entry& e, char const* msg)
{
	e["z"] = "e";
	entry::list_type& l = e["e"].list();
	l.push_back(entry(203));
	l.push_back(entry(msg));
}

// build response
void node_impl::incoming_request(msg const& m, entry& e)
{
	e = entry(entry::dictionary_t);
	e["z"] = "r";
	e["t"] = m.message.dict_find_string_value("t");

	key_desc_t top_desc[] = {
		{"q", lazy_entry::string_t, 0, 0},
		{"x", lazy_entry::dict_t, 0, key_desc_t::parse_children},
			{"id", lazy_entry::string_t, 20, key_desc_t::last_child},
	};

	lazy_entry const* top_level[3];
	char error_string[200];
	if (!verify_message(&m.message, top_desc, top_level, 3, error_string, sizeof(error_string)))
	{
		incoming_error(e, error_string);
		return;
	}

	char const* query = top_level[0]->string_cstr();

	lazy_entry const* arg_ent = top_level[1];

	node_id id(top_level[2]->string_ptr());

	m_table.heard_about(id, m.addr);

	entry& reply = e["r"];
	m_rpc.add_our_id(reply);

	// if this nodes ID doesn't match its IP, tell it what
	// its IP is
	if (!verify_id(id, m.addr.address())) {
		reply["ip"] = address_to_bytes(m.addr.address());
		//[MF] enforce ID verification.
		return;
	}

	if (strcmp(query, "ping") == 0)
	{
		// we already have 't' and 'id' in the response
		// no more left to add
	}
	/*
	else if (strcmp(query, "getPeers") == 0)
	{
		key_desc_t msg_desc[] = {
			{"infoHash", lazy_entry::string_t, 20, 0},
			{"ifhpfxl", lazy_entry::int_t, 0, key_desc_t::optional},
			{"noseed", lazy_entry::int_t, 0, key_desc_t::optional},
			{"scrape", lazy_entry::int_t, 0, key_desc_t::optional},
		};

		lazy_entry const* msg_keys[4];
		if (!verify_message(arg_ent, msg_desc, msg_keys, 4, error_string, sizeof(error_string)))
		{
			incoming_error(e, error_string);
			return;
		}

		reply["token"] = generate_token(m.addr, msg_keys[0]->string_ptr());
		
		sha1_hash info_hash(msg_keys[0]->string_ptr());
		nodes_t n;
		// always return nodes as well as peers
		m_table.find_node(info_hash, n, 0);
		write_nodes_entry(reply, n);

		int prefix = msg_keys[1] ? int(msg_keys[1]->int_value()) : 20;
		if (prefix > 20) prefix = 20;
		else if (prefix < 4) prefix = 4;

		bool noseed = false;
		bool scrape = false;
		if (msg_keys[2] && msg_keys[2]->int_value() != 0) noseed = true;
		if (msg_keys[3] && msg_keys[3]->int_value() != 0) scrape = true;
		lookup_peers(info_hash, prefix, reply, noseed, scrape);
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		if (reply.find_key("values"))
		{
			TORRENT_LOG(node) << " values: " << reply["values"].list().size();
		}
#endif
	}*/
	else if (strcmp(query, "findNode") == 0)
	{
		key_desc_t msg_desc[] = {
			{"target", lazy_entry::string_t, 20, 0},
		};

		lazy_entry const* msg_keys[1];
		if (!verify_message(arg_ent, msg_desc, msg_keys, 1, error_string, sizeof(error_string)))
		{
			incoming_error(e, error_string);
			return;
		}

		sha1_hash target(msg_keys[0]->string_ptr());

		// TODO: 1 find_node should write directly to the response entry
		nodes_t n;
		m_table.find_node(target, n, 0);
		write_nodes_entry(reply, n);
	}
	else if (strcmp(query, "announcePeer") == 0)
	{
		key_desc_t msg_desc[] = {
			{"infoHash", lazy_entry::string_t, 20, 0},
			{"port", lazy_entry::int_t, 0, 0},
			{"token", lazy_entry::string_t, 0, 0},
			{"n", lazy_entry::string_t, 0, key_desc_t::optional},
			{"seed", lazy_entry::int_t, 0, key_desc_t::optional},
			{"implied_port", lazy_entry::int_t, 0, key_desc_t::optional},
		};

		lazy_entry const* msg_keys[6];
		if (!verify_message(arg_ent, msg_desc, msg_keys, 6, error_string, sizeof(error_string)))
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			++g_failed_announces;
#endif
			incoming_error(e, error_string);
			return;
		}

		int port = int(msg_keys[1]->int_value());

		// is the announcer asking to ignore the explicit
		// listen port and instead use the source port of the packet?
		if (msg_keys[5] && msg_keys[5]->int_value() != 0)
			port = m.addr.port();

		if (port < 0 || port >= 65536)
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			++g_failed_announces;
#endif
			incoming_error(e, "invalid port");
			return;
		}

		sha1_hash info_hash(msg_keys[0]->string_ptr());

		if (m_post_alert)
		{
			alert* a = new dht_announce_alert(m.addr.address(), port, info_hash);
			if (!m_post_alert->post_alert(a)) delete a;
		}

		if (!verify_token(msg_keys[2]->string_value(), msg_keys[0]->string_ptr(), m.addr))
		{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			++g_failed_announces;
#endif
			incoming_error(e, "invalid token");
			return;
		}

		// the token was correct. That means this
		// node is not spoofing its address. So, let
		// the table get a chance to add it.
		m_table.node_seen(id, m.addr, 0xffff);

		if (!m_map.empty() && int(m_map.size()) >= m_settings.max_torrents)
		{
			// we need to remove some. Remove the ones with the
			// fewest peers
			int num_peers = m_map.begin()->second.peers.size();
			table_t::iterator candidate = m_map.begin();
			for (table_t::iterator i = m_map.begin()
				, end(m_map.end()); i != end; ++i)
			{
				if (int(i->second.peers.size()) > num_peers) continue;
				if (i->first == info_hash) continue;
				num_peers = i->second.peers.size();
				candidate = i;
			}
			m_map.erase(candidate);
		}

		add_peer( msg_keys[3] ? msg_keys[3]->string_value() : std::string(), info_hash,
				  m.addr.address(), port, msg_keys[4] && msg_keys[4]->int_value(), 0);

#ifdef TORRENT_DHT_VERBOSE_LOGGING
		++g_announces;
#endif
	}
	else if (strcmp(query, "putData") == 0)
	{
		const static key_desc_t msg_desc[] = {
			{"token", lazy_entry::string_t, 0, 0},
			{"sig_p", lazy_entry::string_t, 0, 0},
			{"sig_user", lazy_entry::string_t, 0, 0},
			{"p", lazy_entry::dict_t, 0, key_desc_t::parse_children},
			    {"v", lazy_entry::none_t, 0, 0},
			    {"seq", lazy_entry::int_t, 0, key_desc_t::optional},
			    {"time", lazy_entry::int_t, 0, 0},
			    {"height", lazy_entry::int_t, 0, 0},
			    {"target", lazy_entry::dict_t, 0, key_desc_t::parse_children},
				{"n", lazy_entry::string_t, 0, 0},
				{"r", lazy_entry::string_t, 0, 0},
				{"t", lazy_entry::string_t, 0, 0},
		};
		enum {mk_token=0, mk_sig_p, mk_sig_user, mk_p, mk_v,
		      mk_seq, mk_time, mk_height, mk_target, mk_n,
		      mk_r, mk_t};

		// attempt to parse the message
		lazy_entry const* msg_keys[12];
		if (!verify_message(arg_ent, msg_desc, msg_keys, 12, error_string, sizeof(error_string)))
		{
			incoming_error(e, error_string);
			return;
		}

		// is this a multi-item?
		bool multi = (msg_keys[mk_t]->string_value() == "m");

		// pointer and length to the whole entry
		std::pair<char const*, int> buf = msg_keys[mk_p]->data_section();
		int maxSize = (multi) ? 768 : 8192; // single is bigger for avatar image etc
		// Note: when increasing maxSize, check m_buf_size @ udp_socket.cpp.
		if (buf.second > maxSize || buf.second <= 0)
		{
			incoming_error(e, "message too big");
			return;
		}

		// "target" must be a dict of 3 entries
		if (msg_keys[mk_target]->dict_size() != 3) {
			incoming_error(e, "target dict size != 3");
			return;
		}

		// target id is hash of bencoded dict "target"
		std::pair<char const*, int> targetbuf = msg_keys[mk_target]->data_section();
		sha1_hash target = hasher(targetbuf.first,targetbuf.second).final();

#ifdef TORRENT_DHT_VERBOSE_LOGGING
		printf("PUT target={%s,%s,%s} from=%s:%d\n"
			, msg_keys[mk_n]->string_value().c_str()
			, msg_keys[mk_r]->string_value().c_str()
			, msg_keys[mk_t]->string_value().c_str()
			, m.addr.address().to_string().c_str(), m.addr.port());
#endif

		// verify the write-token. tokens are only valid to write to
		// specific target hashes. it must match the one we got a "get" for
		if (!verify_token(msg_keys[mk_token]->string_value(), (char const*)&target[0], m.addr))
		{
			incoming_error(e, "invalid token");
			return;
		}

		std::pair<char const*, int> bufp = msg_keys[mk_p]->data_section();
		std::string str_p(bufp.first,bufp.second);
		if (!verifySignature(str_p,
				    msg_keys[mk_sig_user]->string_value(),
				    msg_keys[mk_sig_p]->string_value())) {
			incoming_error(e, "invalid signature");
			return;
		}

		if (!multi && msg_keys[mk_sig_user]->string_value() !=
			      msg_keys[mk_n]->string_value() ) {
			incoming_error(e, "only owner is allowed");
			return;
		}

		/* we can't check username, otherwise we break hashtags etc.
		if (multi && !usernameExists(msg_keys[mk_n]->string_value())) {
			incoming_error(e, "unknown user for resource");
			return;
		}
		*/

		if (msg_keys[mk_r]->string_value().size() > 32) {
			incoming_error(e, "resource name too big");
			return;
		}

		if (!multi && (!msg_keys[mk_seq] || msg_keys[mk_seq]->int_value() < 0)) {
			incoming_error(e, "seq is required for single");
			return;
		}

		if (msg_keys[mk_height]->int_value() > getBestHeight()+1 && getBestHeight() > 0) {
			incoming_error(e, "height > getBestHeight");
			return;
		}

		if (msg_keys[mk_time]->int_value() > GetAdjustedTime() + MAX_TIME_IN_FUTURE) {
			incoming_error(e, "time > GetAdjustedTime");
			return;
		}

		m_table.node_seen(id, m.addr, 0xffff);
		//f->last_seen = time_now();

		// check distance between target, nodes and our own id
		// n is sorted from closer(begin) to more distant (end)
		nodes_t n;
		m_table.find_node(target, n, 0, m_table.bucket_size() * 2);
		bool possiblyNeighbor = false;
		if( n.size() < m_table.bucket_size() ) {
			possiblyNeighbor = true;
		} else {
			node_id dFarther = distance(n.back().id, target);
			node_id dOwn     = distance(nid(), target);
			if( dOwn < dFarther )
				possiblyNeighbor = true;
		}
		// possiblyNeighbor is authoritative for false, so we may
		// trust it to NOT store this value. someone might be trying to
		// attack this resource by storing value into non-final nodes.
		if( !possiblyNeighbor ) {
#ifdef TORRENT_DHT_VERBOSE_LOGGING
			printf("putData with possiblyNeighbor=false, ignoring request.\n");
#endif
			return;
		}

		dht_storage_item item(str_p, msg_keys[mk_sig_p], msg_keys[mk_sig_user]);
		std::pair<char const*, int> bufv = msg_keys[mk_v]->data_section();
		if( store_dht_item(item, target, multi, !multi ? msg_keys[mk_seq]->int_value() : 0,
		                   msg_keys[mk_height]->int_value(), bufv) ) {
			process_newly_stored_entry(*msg_keys[mk_p]);
		}
	}
	else if (strcmp(query, "getData") == 0)
	{
		key_desc_t msg_desc[] = {
			{"justtoken", lazy_entry::int_t, 0, key_desc_t::optional},
			{"target", lazy_entry::dict_t, 0, key_desc_t::parse_children},
				{"n", lazy_entry::string_t, 0, 0},
				{"r", lazy_entry::string_t, 0, 0},
				{"t", lazy_entry::string_t, 0, 0},
		};
		enum {mk_justtoken=0, mk_target, mk_n, mk_r, mk_t};

		// attempt to parse the message
		lazy_entry const* msg_keys[5];
		if (!verify_message(arg_ent, msg_desc, msg_keys, 5, error_string, sizeof(error_string)))
		{
			incoming_error(e, error_string);
			return;
		}

		// "target" must be a dict of 3 entries
		if (msg_keys[mk_target]->dict_size() != 3) {
			incoming_error(e, "target dict size != 3");
			return;
		}

		if (msg_keys[mk_t]->string_value() != "s" &&
			msg_keys[mk_t]->string_value() != "m") {
			incoming_error(e, "invalid target.t value");
			return;
		}

		// target id is hash of bencoded dict "target"
		std::pair<char const*, int> targetbuf = msg_keys[mk_target]->data_section();
		sha1_hash target = hasher(targetbuf.first,targetbuf.second).final();

		bool justtoken = false;
		if (msg_keys[mk_justtoken] && msg_keys[mk_justtoken]->int_value() != 0) justtoken = true;

#ifdef TORRENT_DHT_VERBOSE_LOGGING
		printf("GET target={%s,%s,%s} from=%s:%d\n"
			, msg_keys[mk_n]->string_value().c_str()
			, msg_keys[mk_r]->string_value().c_str()
			, msg_keys[mk_t]->string_value().c_str()
			, m.addr.address().to_string().c_str(), m.addr.port());
#endif
		reply["token"] = generate_token(m.addr, target.to_string().c_str());

		nodes_t n;
		// always return nodes as well as peers
		m_table.find_node(target, n, 0);
		write_nodes_entry(reply, n);

		bool hasData = false;

		if( msg_keys[mk_r]->string_value() == "tracker" ) {
			lookup_peers(target, 20, reply, false, false);
			entry::list_type& pe = reply["values"].list();
			//printf("tracker=> replying with %d peers\n", pe.size());
		} else {
			dht_storage_table_t::iterator i = m_storage_table.find(target);
			if (i != m_storage_table.end())
			{
				hasData = true;
				reply["data"] = entry::list_type();
				entry::list_type &values = reply["data"].list();

				dht_storage_list_t const& lsto = i->second;
				for (dht_storage_list_t::const_iterator j = lsto.begin()
					  , end(lsto.end()); j != end && !justtoken; ++j)
				{
					entry::dictionary_type v;
					v["p"] = bdecode(j->p.begin(), j->p.end());
					v["sig_p"] = j->sig_p;
					v["sig_user"] = j->sig_user;
					values.push_back(v);
				}
			}
		}

		// check distance between target, nodes and our own id
		// n is sorted from closer(begin) to more distant (end)
		bool possiblyNeighbor = false;
		if( n.size() < m_table.bucket_size() ) {
			possiblyNeighbor = true;
		} else {
			node_id dFarther = distance(n.back().id, target);
			node_id dOwn     = distance(nid(), target);
			if( dOwn < dFarther )
				possiblyNeighbor = true;
		}

		if (m_post_alert)
		{
			entry eTarget;
			eTarget = *msg_keys[mk_target];
			alert* a = new dht_get_data_alert(eTarget,possiblyNeighbor,hasData);
			if (!m_post_alert->post_alert(a)) delete a;
		}
	}
	else
	{
		// if we don't recognize the message but there's a
		// 'target' or 'infoHash' in the arguments, treat it
		// as find_node to be future compatible
		lazy_entry const* target_ent = arg_ent->dict_find_string("target");
		if (target_ent == 0 || target_ent->string_length() != 20)
		{
			target_ent = arg_ent->dict_find_string("infoHash");
			if (target_ent == 0 || target_ent->string_length() != 20)
			{
				incoming_error(e, "unknown message");
				return;
			}
		}

		sha1_hash target(target_ent->string_ptr());
		nodes_t n;
		// always return nodes as well as peers
		m_table.find_node(target, n, 0);
		write_nodes_entry(reply, n);
		return;
	}
}

bool node_impl::store_dht_item(dht_storage_item &item, const big_number &target, 
                               bool multi, int seq, int height, std::pair<char const*, int> &bufv)
{
    bool stored = false;
    
    item.next_refresh_time = getNextRefreshTime(item.confirmed);
    if( m_next_storage_refresh > item.next_refresh_time ) {
        m_next_storage_refresh = item.next_refresh_time;
    }

    dht_storage_table_t::iterator i = m_storage_table.find(target);
    if (i == m_storage_table.end()) {
        // make sure we don't add too many items
        if (int(m_storage_table.size()) >= m_settings.max_dht_items)
        {
            // FIXME: erase one? preferably a multi
        }

        dht_storage_list_t to_add;
        to_add.push_back(item);

        boost::tie(i, boost::tuples::ignore) = m_storage_table.insert(
            std::make_pair(target, to_add));
        stored = true;
    } else {
        dht_storage_list_t & lsto = i->second;

        dht_storage_list_t::reverse_iterator j, rend(lsto.rend());
        dht_storage_list_t::iterator insert_pos = lsto.end();
        for( j = lsto.rbegin(); j != rend; ++j) {
            dht_storage_item &olditem = *j;

            lazy_entry p;
            int pos;
            error_code err;
            // FIXME: optimize to avoid bdecode (store seq separated, etc)
            int ret = lazy_bdecode(olditem.p.data(), olditem.p.data() + olditem.p.size(), p, err, &pos, 10, 500);

            if( !multi ) {
                if( seq > p.dict_find_int("seq")->int_value() ) {
                    olditem = item;
                    stored = true;
                } else {
                    // don't report this error (because of refresh storage)
                    //incoming_error(e, "old sequence number");
                    break;
                }
            } else {
                // compare contents before adding to the list
                std::pair<char const*, int> bufoldv = p.dict_find("v")->data_section();
                if( bufv.second == bufoldv.second && !memcmp(bufv.first, bufoldv.first,bufv.second) ) {
                    // break so it wont be inserted
                    break;
                }

                // if new entry is newer than existing one, it will be inserted before
                if( height >= p.dict_find_int_value("height") ) {
                    insert_pos = j.base();
                    insert_pos--;
                }
            }
        }
        if(multi && j == rend) {
            // new entry
            lsto.insert(insert_pos, item);
            stored = true;
        }

        if(lsto.size() > m_settings.max_entries_per_multi) {
            lsto.resize(m_settings.max_entries_per_multi);
        }
    }
    return stored;
}

} } // namespace libtorrent::dht

