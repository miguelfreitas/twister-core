#include "twister_utils.h"

#include <libtorrent/session.hpp>

#include <stdio.h>

using namespace std;

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


