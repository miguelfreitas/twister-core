#include "twister_utils.h"

#include <libtorrent/session.hpp>
#include <libtorrent/bencode.hpp>

#include <boost/foreach.hpp>

#include <stdio.h>

using namespace std;
using namespace boost;

twister_utils::twister_utils()
{
}

int load_file(std::string const& filename, std::vector<char>& v, int limit)
{
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL)
		return -1;
	int r = fseek(f, 0, SEEK_END);
	if (r != 0) {
		fclose(f);
		return -1;
	}
	long s = ftell(f);
	if (s < 0) {
		fclose(f);
		return -1;
	}

	if (s > limit) {
		fclose(f);
		return -2;
	}

	r = fseek(f, 0, SEEK_SET);
	if (r != 0) {
		fclose(f);
		return -1;
	}

	v.resize(s);
	if (s == 0) {
		fclose(f);
		return 0;
	}

	r = fread(&v[0], 1, v.size(), f);
	if (r < 0) {
		fclose(f);
		return -1;
	}

	fclose(f);

	if (r != s) return -3;

	return 0;
}

int save_file(std::string const& filename, std::vector<char>& v)
{
	using namespace libtorrent;

	// TODO: don't use internal file type here. use fopen()
	file f;
	error_code ec;
	if (!f.open(filename, file::write_only, ec)) return -1;
	if (ec) return -1;
	file::iovec_t b = {&v[0], v.size()};
	size_type written = f.writev(0, &b, 1, ec);
	if (written != int(v.size())) return -3;
	if (ec) return -3;
	return 0;
}

using namespace json_spirit;
using namespace libtorrent;

Value entryToJson(const entry &e)
{
    Array lst;
    Object o;
    switch( e.type() ) {
        case entry::int_t:
            return e.integer();
        case entry::string_t:
            return e.string();
        case entry::list_t:
            for (entry::list_type::const_iterator i = e.list().begin(); i != e.list().end(); ++i) {
                lst.push_back( entryToJson(*i) );
            }
            return lst;
        case entry::dictionary_t:
            for (entry::dictionary_type::const_iterator i = e.dict().begin(); i != e.dict().end(); ++i) {
                o.push_back(Pair(i->first, entryToJson(i->second)));
            }
            return o;
        default:
            return string("<uninitialized>");
    }
}

entry jsonToEntry(const Value &v)
{
    entry::list_type lst;
    entry::dictionary_type dict;

    switch( v.type() ) {
        case int_type:
            return v.get_int();
        case str_type:
            return v.get_str();
        case array_type:
            for (Array::const_iterator i = v.get_array().begin(); i != v.get_array().end(); ++i) {
                lst.push_back( jsonToEntry(*i) );
            }
            return lst;
        case obj_type:
            for (Object::const_iterator i = v.get_obj().begin(); i != v.get_obj().end(); ++i) {
                dict[ i->name_ ] = jsonToEntry(i->value_);
            }
            return dict;
        default:
            return string("<uninitialized>");
    }
}


int saveUserData(std::string const& filename, std::map<std::string,UserData> const &users)
{
    entry userEntry;

    std::map<std::string,UserData>::const_iterator i;
    for (i = users.begin(); i != users.end(); ++i) {
        UserData const &data = i->second;

        entry &dataEntry = userEntry[i->first];
        entry &followingEntry = dataEntry["following"];
        BOOST_FOREACH( std::string const &n, data.m_following) {
            followingEntry.list().push_back(n);
        }

        entry &dmEntry = dataEntry["dm"];

        std::map<std::string, std::list<StoredDirectMsg> >::const_iterator j;
        for (j = data.m_directmsg.begin(); j != data.m_directmsg.end(); ++j) {
            std::list<StoredDirectMsg> const &stoDmList = j->second;

            entry &stoDmLstEntry = dmEntry[j->first];
            BOOST_FOREACH( StoredDirectMsg const &dm, stoDmList) {
                entry stoDmEntry;
                stoDmEntry["time"] = dm.m_utcTime;
                stoDmEntry["text"] = dm.m_text;
                stoDmEntry["fromMe"] = dm.m_fromMe;
                stoDmLstEntry.list().push_back(stoDmEntry);
            }
        }
    }

    std::vector<char> buf;
    bencode(std::back_inserter(buf), userEntry);

    return save_file(filename, buf);
}


int loadUserData(std::string const& filename, std::map<std::string,UserData> &users)
{
    std::vector<char> in;
    if (load_file(filename, in) == 0) {
        lazy_entry userEntry;
        error_code ec;
        if (lazy_bdecode(&in[0], &in[0] + in.size(), userEntry, ec) == 0) {
            for( int i = 0; i < userEntry.dict_size(); i++) {
                UserData data;

                const lazy_entry *dataEntry = userEntry.dict_at(i).second;
                const lazy_entry *followingEntry = dataEntry->dict_find("following");
                for( int j = 0; j < followingEntry->list_size(); j++ ) {
                    data.m_following.insert( followingEntry->list_string_value_at(j) );
                }

                const lazy_entry *dmEntry = dataEntry->dict_find("dm");
                for( int j = 0; j < dmEntry->dict_size(); j++ ) {
                    const lazy_entry *stoDmLstEntry = dmEntry->dict_at(j).second;

                    for( int k = 0; k < stoDmLstEntry->list_size(); k++ ) {
                        const lazy_entry *stoDmEntry = stoDmLstEntry->list_at(k);
                        StoredDirectMsg dm;
                        dm.m_text    = stoDmEntry->dict_find_string_value("text");
                        dm.m_utcTime = stoDmEntry->dict_find_int_value("time");
                        dm.m_fromMe  = stoDmEntry->dict_find_int_value("fromMe");
                        data.m_directmsg[dmEntry->dict_at(j).first].push_back(dm);
                    }
                }

                users[userEntry.dict_at(i).first] = data;
            }
            return 0;
        }
    }
    return -1;
}


