#include "twister_utils.h"

#include "util.h"

#include <libtorrent/session.hpp>
#include <libtorrent/bencode.hpp>

#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

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
	libtorrent::error_code ec;
	if (!f.open(filename, file::write_only, ec)) return -1;
	if (ec) return -1;
	f.set_size(0, ec);
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
    entry userDict;

    std::map<std::string,UserData>::const_iterator i;
    for (i = users.begin(); i != users.end(); ++i) {
        UserData const &udata = i->second;

        if( udata.m_following.size() ) {
            entry &userData = userDict[i->first];
            entry &followingList = userData["following"];
            BOOST_FOREACH( std::string const &n, udata.m_following) {
                followingList.list().push_back(n);
            }
        }

        if( udata.m_mentionsPosts.size() ) {
            entry &userData = userDict[i->first];
            entry &mentionsList = userData["mentions"];
            BOOST_FOREACH( libtorrent::entry const &mention, udata.m_mentionsPosts) {
                mentionsList.list().push_back(mention);
            }
        }

        if( udata.m_directmsg.size() ) {
            entry &userData = userDict[i->first];
            entry &dmDict = userData["dm"];

            std::map<std::string, std::vector<StoredDirectMsg> >::const_iterator j;
            for (j = udata.m_directmsg.begin(); j != udata.m_directmsg.end(); ++j) {
                entry &dmList = dmDict[j->first];
                BOOST_FOREACH( StoredDirectMsg const &stoDm, j->second) {
                    entry dmElem;
                    dmElem["time"]   = stoDm.m_utcTime;
                    dmElem["text"]   = stoDm.m_text;
                    dmElem["fromMe"] = stoDm.m_fromMe;
                    dmElem["from"]   = stoDm.m_from;
                    dmElem["k"]      = stoDm.m_k;
                    dmList.list().push_back(dmElem);
                }
            }
        }

        if( udata.m_ignoreGroups.size() ) {
            entry &userData = userDict[i->first];
            entry &ignoreGroupsList = userData["ignore_groups"];
            BOOST_FOREACH( std::string const &n, udata.m_ignoreGroups) {
                ignoreGroupsList.list().push_back(n);
            }
        }
    }

    std::vector<char> buf;
    if( userDict.type() == entry::dictionary_t ) {
        bencode(std::back_inserter(buf), userDict);
        return save_file(filename, buf);
    } else {
        return 0;
    }
}


int loadUserData(std::string const& filename, std::map<std::string,UserData> &users)
{
    std::vector<char> in;
    if (load_file(filename, in) == 0) {
        lazy_entry userDict;
        libtorrent::error_code ec;
        if (lazy_bdecode(&in[0], &in[0] + in.size(), userDict, ec) == 0) {
            if( userDict.type() != lazy_entry::dict_t ) goto data_error;

            for( int i = 0; i < userDict.dict_size(); i++) {
                UserData udata;

                const lazy_entry *userData = userDict.dict_at(i).second;
                if( userData->type() != lazy_entry::dict_t ) goto data_error;

                const lazy_entry *followingList = userData->dict_find("following");
                if( followingList ) {
                    if( followingList->type() != lazy_entry::list_t ) goto data_error;

                    for( int j = 0; j < followingList->list_size(); j++ ) {
                        udata.m_following.insert( followingList->list_string_value_at(j) );
                    }
                }

                const lazy_entry *mentionsList = userData->dict_find("mentions");
                if( mentionsList ) {
                    if( mentionsList->type() != lazy_entry::list_t ) goto data_error;

                    for( int j = 0; j < mentionsList->list_size(); j++ ) {
                        const lazy_entry *v = mentionsList->list_at(j);
                        if( v->type() != lazy_entry::dict_t ) goto data_error;
                        lazy_entry const* post = v->dict_find_dict("userpost");
                        if( !post ) goto data_error;
                        
                        std::string username = post->dict_find_string_value("n");
                        int64 time = post->dict_find_int_value("time",-1);
                        std::string postKey = username + ";" + boost::lexical_cast<std::string>(time);
                        udata.m_mentionsKeys.insert(postKey);
                        
                        entry vEntry;
                        vEntry = *v;
                        udata.m_mentionsPosts.push_back( vEntry );
                    }
                }

                const lazy_entry *dmDict = userData->dict_find("dm");
                if( dmDict ) {
                    if( dmDict->type() != lazy_entry::dict_t ) goto data_error;

                    for( int j = 0; j < dmDict->dict_size(); j++ ) {
                        const lazy_entry *dmList = dmDict->dict_at(j).second;
                        if( !dmList || dmList->type() != lazy_entry::list_t ) goto data_error;

                        for( int k = 0; k < dmList->list_size(); k++ ) {
                            const lazy_entry *dmElem = dmList->list_at(k);
                            if( dmElem->type() != lazy_entry::dict_t ) goto data_error;

                            StoredDirectMsg stoDm;
                            stoDm.m_text    = dmElem->dict_find_string_value("text");
                            stoDm.m_utcTime = dmElem->dict_find_int_value("time");
                            stoDm.m_fromMe  = dmElem->dict_find_int_value("fromMe");
                            stoDm.m_from    = dmElem->dict_find_string_value("from");
                            stoDm.m_k       = dmElem->dict_find_int_value("k",-1);
                            udata.m_directmsg[dmDict->dict_at(j).first].push_back(stoDm);
                        }
                    }
                }

                const lazy_entry *ignoreGroupsList = userData->dict_find("ignore_groups");
                if( ignoreGroupsList ) {
                    if( ignoreGroupsList->type() != lazy_entry::list_t ) goto data_error;

                    for( int j = 0; j < ignoreGroupsList->list_size(); j++ ) {
                        udata.m_ignoreGroups.insert( ignoreGroupsList->list_string_value_at(j) );
                    }
                }

                users[userDict.dict_at(i).first] = udata;
            }
            return 0;
        }
    }
    return -1;

data_error:
    printf("loadUserData: unexpected bencode type - user_data corrupt!\n");
    return -2;
}

int saveGroupData(std::string const& filename, std::map<std::string,GroupChat> const &groups)
{
    entry groupsDict;

    std::map<std::string,GroupChat>::const_iterator i;
    for (i = groups.begin(); i != groups.end(); ++i) {
        GroupChat const &gchat = i->second;
        entry &groupData = groupsDict[i->first];
        groupData["description"] = gchat.m_description;
        groupData["privkey"] = gchat.m_privKey;

        if( gchat.m_members.size() ) {
            entry &membersList = groupData["members"];
            BOOST_FOREACH( std::string const &n, gchat.m_members) {
                membersList.list().push_back(n);
            }
        }
    }

    std::vector<char> buf;
    if( groupsDict.type() == entry::dictionary_t ) {
        bencode(std::back_inserter(buf), groupsDict);
        return save_file(filename, buf);
    } else {
        return 0;
    }
}


int loadGroupData(std::string const& filename, std::map<std::string,GroupChat> &groups)
{
    std::vector<char> in;
    if (load_file(filename, in) == 0) {
        lazy_entry groupsDict;
        libtorrent::error_code ec;
        if (lazy_bdecode(&in[0], &in[0] + in.size(), groupsDict, ec) == 0) {
            if( groupsDict.type() != lazy_entry::dict_t ) goto data_error;

            for( int i = 0; i < groupsDict.dict_size(); i++) {
                GroupChat gchat;

                const lazy_entry *groupData = groupsDict.dict_at(i).second;
                if( groupData->type() != lazy_entry::dict_t ) goto data_error;

                gchat.m_description = groupData->dict_find_string_value("description");
                gchat.m_privKey = groupData->dict_find_string_value("privkey");

                const lazy_entry *membersList = groupData->dict_find("members");
                if( membersList ) {
                    if( membersList->type() != lazy_entry::list_t ) goto data_error;

                    for( int j = 0; j < membersList->list_size(); j++ ) {
                        gchat.m_members.insert( membersList->list_string_value_at(j) );
                    }
                }
                groups[groupsDict.dict_at(i).first] = gchat;
            }
            return 0;
        }
    }
    return -1;

data_error:
    printf("loadGroupData: unexpected bencode type - user_data corrupt!\n");
    return -2;
}


void findAndHexcape(libtorrent::entry &e, string const& key)
{
    if( e.type() == libtorrent::entry::dictionary_t &&
        e.find_key(key) && e[key].type() == libtorrent::entry::string_t ) {
        e[key] = HexStr(e[key].string());
    }
}

void findAndUnHexcape(libtorrent::entry &e, string const& key)
{
    if( e.type() == libtorrent::entry::dictionary_t &&
        e.find_key(key) && e[key].type() == libtorrent::entry::string_t ) {
        vector<unsigned char> vch = ParseHex(e[key].string());
        e[key] = string((const char *)vch.data(), vch.size());
    }
}

void hexcapePost(libtorrent::entry &e)
{
    if( e.type() == libtorrent::entry::dictionary_t ) {
        findAndHexcape(e,"sig_userpost");
        findAndHexcape(e,"sig_wort");
        if( e.find_key("userpost") ) {
            entry &userpost = e["userpost"];
            if( userpost.type() == libtorrent::entry::dictionary_t ) {
                findAndHexcape(userpost,"sig_rt");
                findAndHexcape(userpost, "sig_fav");
                if( userpost.find_key("dm") ) {
                    entry &dm = userpost["dm"];
                    if( dm.type() == libtorrent::entry::dictionary_t ) {
                        findAndHexcape(dm,"body");
                        findAndHexcape(dm,"key");
                        findAndHexcape(dm,"mac");
                    }
                } else if( userpost.find_key("pfav") ) {
                    entry &pfav = userpost["pfav"];
                    if( pfav.type() == libtorrent::entry::dictionary_t ) {
                        findAndHexcape(pfav,"body");
                        findAndHexcape(pfav,"key");
                        findAndHexcape(pfav,"mac");
                    }
                }
            }
        }
    }
}

void unHexcapePost(libtorrent::entry &e)
{
    if( e.type() == libtorrent::entry::dictionary_t ) {
        findAndUnHexcape(e,"sig_userpost");
        if( e.find_key("userpost") ) {
            entry &userpost = e["userpost"];
            if( userpost.type() == libtorrent::entry::dictionary_t ) {
                findAndUnHexcape(userpost,"sig_rt");
                if( userpost.find_key("dm") ) {
                    entry &dm = userpost["dm"];
                    if( dm.type() == libtorrent::entry::dictionary_t ) {
                        findAndUnHexcape(dm,"body");
                        findAndUnHexcape(dm,"key");
                        findAndUnHexcape(dm,"mac");
                    }
                }
            }
        }
    }
}

void hexcapeDht(libtorrent::entry &e)
{
    if( e.type() == libtorrent::entry::dictionary_t ) {
        findAndHexcape(e,"sig_p");
        if( e.find_key("p") ) {
            entry &p = e["p"];
            if( p.type() == libtorrent::entry::dictionary_t ) {
                if( p.find_key("v") ) {
                    entry &v = p["v"];
                    if( v.type() == libtorrent::entry::dictionary_t ) {
                        hexcapePost(v);
                        // any other possible content to hexcape?
                    }
                }
            }
        }
    }
}

void unHexcapeDht(libtorrent::entry &e)
{
    if( e.type() == libtorrent::entry::dictionary_t ) {
        findAndUnHexcape(e,"sig_p");
        if( e.find_key("p") ) {
            entry &p = e["p"];
            if( p.type() == libtorrent::entry::dictionary_t ) {
                if( p.find_key("v") ) {
                    entry &v = p["v"];
                    if( v.type() == libtorrent::entry::dictionary_t ) {
                        unHexcapePost(v);
                        // any other possible content to unhexcape?
                    }
                }
            }
        }
    }
}

std::string safeGetEntryString(libtorrent::entry const &e, std::string const& key)
{
    if( e.type() == libtorrent::entry::dictionary_t &&
        e.find_key(key) && e[key].type() == libtorrent::entry::string_t ) {
        return e[key].string();
    } else {
        return "";
    }
}

int safeGetEntryInt(libtorrent::entry const &e, std::string const& key)
{
    if( e.type() == libtorrent::entry::dictionary_t &&
        e.find_key(key) && e[key].type() == libtorrent::entry::int_t ) {
        return e[key].integer();
    } else {
        return 0;
    }
}

libtorrent::entry safeGetEntryDict(libtorrent::entry const &e, std::string const& key)
{
    static libtorrent::entry::dictionary_type dummy;
    if( e.type() == libtorrent::entry::dictionary_t &&
        e.find_key(key) && e[key].type() == libtorrent::entry::dictionary_t ) {
        return e[key].dict();
    } else {
        return dummy;
    }
}

sha1_hash dhtTargetHash(std::string const &username, std::string const &resource, std::string const &type)
{
    entry target;
    target["n"] = username;
    target["r"] = resource;
    target["t"] = type;

    std::vector<char> buf;
    bencode(std::back_inserter(buf), target);
    return hasher(buf.data(), buf.size()).final();
}

std::string getRandomGroupAlias()
{
    std::string groupAlias("*xxxxxxxx");
    
    for(int i = 1; i < groupAlias.length(); i++) {
        groupAlias[i] = 'a' + 26 * (rand() / (RAND_MAX + 1.0));
    }
    return groupAlias;
}
