#ifndef TWISTER_RSS_H
#define TWISTER_RSS_H

#include "json/json_spirit.h"
#include <string>

enum RSSResultCode
{
    RSS_OK 		   =  0,
    RSS_ERROR_NO_ACCOUNT   = -1,
    RSS_ERROR_BAD_ACCOUNT  = -2,
    RSS_ERROR_NOT_A_NUMBER = -3
};

extern bool sortByTime (json_spirit::Object i,json_spirit::Object j);
extern int generateRSS(std::string uri, std::string *output);

#endif // TWISTER_RSS_H
