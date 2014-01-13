#ifndef TWISTER_UTILS_H
#define TWISTER_UTILS_H

#include "json/json_spirit.h"
#include "libtorrent/entry.hpp"

#include <string>
#include <vector>
#include <set>

// in-memory unencrypted DMs
struct StoredDirectMsg {
    int64_t m_utcTime;
    std::string m_text;
    bool m_fromMe;
};

// in-memory data per wallet user
struct UserData {
    std::set<std::string> m_following;
    // m_directmsg key is the other username
    std::map<std::string, std::vector<StoredDirectMsg> > m_directmsg;
};


class twister_utils
{
public:
    twister_utils();
};

int load_file(std::string const& filename, std::vector<char>& v, int limit = 8000000);
int save_file(std::string const& filename, std::vector<char>& v);

json_spirit::Value entryToJson(const libtorrent::entry &e);
libtorrent::entry jsonToEntry(const json_spirit::Value &v);

int saveUserData(std::string const& filename, std::map<std::string,UserData> const &users);
int loadUserData(std::string const& filename, std::map<std::string,UserData> &users);

void hexcapePost(libtorrent::entry &e);
void unHexcapePost(libtorrent::entry &e);

void hexcapeDht(libtorrent::entry &e);
void unHexcapeDht(libtorrent::entry &e);

std::string safeGetEntryString(libtorrent::entry &e, std::string const& key);

#endif // TWISTER_UTILS_H
