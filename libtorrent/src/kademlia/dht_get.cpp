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

#include "../../src/twister.h"

#include "libtorrent/pch.hpp"

#include <libtorrent/kademlia/dht_get.hpp>
#include <libtorrent/kademlia/routing_table.hpp>
#include <libtorrent/kademlia/rpc_manager.hpp>
#include <libtorrent/kademlia/node.hpp>
#include <libtorrent/io.hpp>
#include <libtorrent/socket.hpp>
#include <libtorrent/socket_io.hpp>
#include <libtorrent/bencode.hpp>
#include <libtorrent/hasher.hpp>
#include <vector>

namespace libtorrent { namespace dht
{

#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_DECLARE_LOG(traversal);
#endif

using detail::read_endpoint_list;
using detail::read_v4_endpoint;
#if TORRENT_USE_IPV6
using detail::read_v6_endpoint;
#endif

void dht_get_observer::reply(msg const& m)
{
	lazy_entry const* r = m.message.dict_find_dict("r");
	if (!r)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(traversal) << "[" << m_algorithm.get() << "] missing response dict";
#endif
		return;
	}

	lazy_entry const* id = r->dict_find_string("id");
	if (!id || id->string_length() != 20)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(traversal) << "[" << m_algorithm.get() << "] invalid id in response";
#endif
		return;
	}
	lazy_entry const* token = r->dict_find_string("token");
	if (token)
	{
		static_cast<dht_get*>(m_algorithm.get())->got_write_token(
			node_id(id->string_ptr()), token->string_value());
	}

	// look for peers
	lazy_entry const* n = r->dict_find_list("data");
	if (n)
	{
#ifdef TORRENT_DHT_VERBOSE_LOGGING
		TORRENT_LOG(traversal)
			<< "[" << m_algorithm.get() << "] GETDATA"
			<< " invoke-count: " << m_algorithm->invoke_count()
			<< " branch-factor: " << m_algorithm->branch_factor()
			<< " addr: " << m.addr
			<< " id: " << node_id(id->string_ptr())
			<< " distance: " << distance_exp(m_algorithm->target(), node_id(id->string_ptr()))
			<< " p: " << ((end - peers) / 6);
#endif
		entry::list_type values_list;
		for (int i = 0; i < n->list_size(); ++i)
		{
			lazy_entry const* e = n->list_at(i);
			if (e->type() != lazy_entry::dict_t) continue;

			lazy_entry const* p = e->dict_find("p");
			lazy_entry const* sig_p = e->dict_find("sig_p");
			lazy_entry const* sig_user = e->dict_find("sig_user");
			if (!p || !sig_p || !sig_user) continue;
			if (p->type() != lazy_entry::dict_t) continue;
			if (sig_p->type() != lazy_entry::string_t) continue;
			if (sig_user->type() != lazy_entry::string_t) continue;

			std::pair<char const*, int> buf = p->data_section();
			if (!verifySignature(std::string(buf.first,buf.second),
					    sig_user->string_value(),
					    sig_p->string_value())) {
#ifdef TORRENT_DHT_VERBOSE_LOGGING
				TORRENT_LOG(traversal) << "dht_get_observer::reply verifySignature failed";
#endif
				continue;
			}
			
			int64 p_time = p->dict_find_int_value("time");
			if(!p_time || p_time > GetAdjustedTime() + MAX_TIME_IN_FUTURE ) {
#ifdef TORRENT_DHT_VERBOSE_LOGGING
				TORRENT_LOG(traversal) << "dht_get_observer::reply invalid time";
#endif
				continue;
			}

			values_list.push_back(entry());
			values_list.back() = *e;
		}
	//printf("dht_get::reply from %s:%d with %d entries\n", m.addr.address().to_string().c_str(), m.addr.port(), values_list.size());
		static_cast<dht_get*>(m_algorithm.get())->got_data(values_list);
	} else {
		// special case for trackers (non-signed content)
		// pretend it is a normal dht resource to the caller
		dht_get *dget( static_cast<dht_get*>(m_algorithm.get()) );
		if( dget->m_targetResource == "tracker" && dget->m_multi ) {
			int followers = r->dict_find_int_value("followers");
			if( followers ) {
				entry::dictionary_type v;
				v["followers"] = followers;
				const lazy_entry *values = r->dict_find_list("values");
				if( values ) {
					v["values_size"] = values->list_size();
					v["values"] = *values;
				}

				entry::dictionary_type target;
				target["n"] = dget->m_targetUser;
				target["r"] = dget->m_targetResource;
				target["t"] = dget->m_multi ? "m" : "s";

				entry::dictionary_type p;
				p["target"] = target;
				p["v"] = v;

				entry::dictionary_type e;
				e["p"] = p;
				entry::list_type values_list;
				values_list.push_back(e);
				dget->got_data(values_list);
			}
		}
	}

	// look for nodes
	n = r->dict_find_string("nodes");
	if (n)
	{
		std::vector<node_entry> node_list;
		char const* nodes = n->string_ptr();
		char const* end = nodes + n->string_length();

		while (end - nodes >= 26)
		{
			node_id id;
			std::copy(nodes, nodes + 20, id.begin());
			nodes += 20;
			m_algorithm->traverse(id, read_v4_endpoint<udp::endpoint>(nodes));
		}
	}

	n = r->dict_find_list("nodes2");
	if (n)
	{
		for (int i = 0; i < n->list_size(); ++i)
		{
			lazy_entry const* p = n->list_at(0);
			if (p->type() != lazy_entry::string_t) continue;
			if (p->string_length() < 6 + 20) continue;
			char const* in = p->string_ptr();

			node_id id;
			std::copy(in, in + 20, id.begin());
			in += 20;
			if (p->string_length() == 6 + 20)
				m_algorithm->traverse(id, read_v4_endpoint<udp::endpoint>(in));
#if TORRENT_USE_IPV6
			else if (p->string_length() == 18 + 20)
				m_algorithm->traverse(id, read_v6_endpoint<udp::endpoint>(in));
#endif
		}
	}
	done();
}

static void add_entry_fun(void* userdata, node_entry const& e)
{
	traversal_algorithm* f = (traversal_algorithm*)userdata;
	f->add_entry(e.id, e.ep(), observer::flag_initial);
}

dht_get::dht_get(
	node_impl& node
	, std::string const &targetUser
	, std::string const &targetResource
	, bool multi
	, data_callback const& dcallback
	, nodes_callback const& ncallback
	, bool justToken
	, bool dontDrop)
	: traversal_algorithm(node, node_id())
	, m_data_callback(dcallback)
	, m_nodes_callback(ncallback)
	, m_target()
	, m_targetUser(targetUser)
	, m_targetResource(targetResource)
	, m_multi(multi)
	, m_done(false)
	, m_got_data(false)
	, m_justToken(justToken)
	, m_dontDrop(dontDrop)
{
	m_target["n"] = m_targetUser;
	m_target["r"] = m_targetResource;
	m_target["t"] = (m_multi) ? "m" : "s";

	std::vector<char> buf;
	bencode(std::back_inserter(buf), m_target);
	sha1_hash target;
	target = hasher(buf.data(), buf.size()).final();
	set_target(target);

#ifdef TORRENT_DHT_VERBOSE_LOGGING
	//TORRENT_LOG(traversal) << "[" << this << "] NEW"
	//	" target: " << target << " k: " << m_node.m_table.bucket_size();
#endif
	node.m_table.for_each_node(&add_entry_fun, 0, (traversal_algorithm*)this);
}

observer_ptr dht_get::new_observer(void* ptr
	, udp::endpoint const& ep, node_id const& id)
{
	observer_ptr o(new (ptr) dht_get_observer(this, ep, id));
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
	o->m_in_constructor = false;
#endif
	return o;
}

bool dht_get::invoke(observer_ptr o)
{
	if (m_done)
	{
		m_invoke_count = -1;
		return false;
	}

	entry e;
	e["z"] = "q";
	e["q"] = "getData";
	entry& a = e["x"];
	entry& target = a["target"];
	target = m_target;
	if (m_justToken) a["justtoken"] = 1;
	o->m_dont_drop = m_dontDrop;
	return m_node.m_rpc.invoke(e, o->target_ep(), o);
}

void dht_get::got_data(entry::list_type const& values_list)
{
	if (!values_list.empty()) m_got_data = true;
	m_data_callback(values_list);
}

void dht_get::done()
{
	if (m_invoke_count != 0) return;

	m_done = true;

#ifdef TORRENT_DHT_VERBOSE_LOGGING
	TORRENT_LOG(traversal) << "[" << this << "] getData DONE";
#endif

	std::vector<std::pair<node_entry, std::string> > results;
	int num_results = m_node.m_table.bucket_size();
	for (std::vector<observer_ptr>::iterator i = m_results.begin()
		, end(m_results.end()); i != end && num_results > 0; ++i)
	{
		observer_ptr const& o = *i;
		if (o->flags & observer::flag_no_id) continue;
		if ((o->flags & observer::flag_queried) == 0) continue;
		std::map<node_id, std::string>::iterator j = m_write_tokens.find(o->id());
		if (j == m_write_tokens.end()) continue;
		results.push_back(std::make_pair(node_entry(o->id(), o->target_ep()), j->second));
		--num_results;
	}
	m_nodes_callback(results, m_got_data, target());

	traversal_algorithm::done();
}

} } // namespace libtorrent::dht

