#ifndef TWISTER_RSS_H
#define TWISTER_RSS_H

#include "json/json_spirit.h"
#include <string>
#include <map>

enum RSSResultCode
{
    RSS_OK 		   =  0,
    RSS_ERROR_NO_ACCOUNT   = -1,
    RSS_ERROR_BAD_ACCOUNT  = -2,
    RSS_ERROR_NOT_A_NUMBER = -3,
    RSS_ERROR_BOOST_REGEX  = -4
};

extern bool sortByTime (json_spirit::Object i,json_spirit::Object j);
extern void encodeXmlCharacters (std::string& data);
#ifdef HAVE_BOOST_REGEX
    extern std::map<std::string, std::string> parseQuery(const std::string& query);
#endif
extern int generateRSS(std::string uri, std::string *output);

#endif // TWISTER_RSS_H
