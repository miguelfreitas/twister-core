/*

Copyright (c) 2006-2012, Arvid Norberg & Daniel Wallin
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

#ifndef DHT_GET_050323_HPP
#define DHT_GET_050323_HPP

#include <vector>
#include <map>

#include <libtorrent/kademlia/traversal_algorithm.hpp>
#include <libtorrent/kademlia/node_id.hpp>
#include <libtorrent/kademlia/routing_table.hpp>
#include <libtorrent/kademlia/rpc_manager.hpp>
#include <libtorrent/kademlia/observer.hpp>
#include <libtorrent/kademlia/msg.hpp>

#include <boost/optional.hpp>
#include <boost/function/function1.hpp>
#include <boost/function/function2.hpp>

namespace libtorrent { namespace dht
{

typedef std::vector<char> packet_t;

class rpc_manager;
class node_impl;

// -------- dht get -----------

class dht_get : public traversal_algorithm
{
public:
	// callback to receive data from "get"
	typedef boost::function<void(entry::list_type const&)> data_callback;

	// callback to receive all write tokens
	typedef boost::function<void(std::vector<std::pair<node_entry, std::string> > const&, bool, node_id)> nodes_callback;

	void got_data(entry::list_type const& values_list);
	void got_write_token(node_id const& n, std::string const& write_token)
	{ m_write_tokens[n] = write_token; }

	dht_get(node_impl& node
		, std::string const &targetUser, std::string const &targetResource, bool multi
		, data_callback const& dcallback
		, nodes_callback const& ncallback
		, bool justToken, bool dontDrop );

	virtual char const* name() const { return "getData"; }

	node_id const target() const { return traversal_algorithm::target(); }

protected:

	void done();
	observer_ptr new_observer(void* ptr, udp::endpoint const& ep, node_id const& id);
	virtual bool invoke(observer_ptr o);

private:

	data_callback m_data_callback;
	nodes_callback m_nodes_callback;
	std::map<node_id, std::string> m_write_tokens;
	entry::dictionary_type m_target;
	std::string const m_targetUser;
	std::string const m_targetResource;
	bool m_multi:1;
	bool m_done:1;
	bool m_got_data:1;
	bool m_justToken:1;
	bool m_dontDrop:1;

	friend class dht_get_observer;
};

class dht_get_observer : public observer
{
public:
	dht_get_observer(
		boost::intrusive_ptr<traversal_algorithm> const& algorithm
		, udp::endpoint const& ep, node_id const& id)
		: observer(algorithm, ep, id)
	{}
	void reply(msg const&);
};

} } // namespace libtorrent::dht

#endif // DHT_GET_050323_HPP

