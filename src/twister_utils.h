#ifndef TWISTER_UTILS_H
#define TWISTER_UTILS_H

#include "json_spirit.h"
#include "libtorrent/entry.hpp"

#include <string>
#include <vector>

class twister_utils
{
public:
    twister_utils();
};

int load_file(std::string const& filename, std::vector<char>& v, int limit = 8000000);
int save_file(std::string const& filename, std::vector<char>& v);

json_spirit::Value entryToJson(const libtorrent::entry &e);
libtorrent::entry jsonToEntry(const json_spirit::Value &v);

#endif // TWISTER_UTILS_H
