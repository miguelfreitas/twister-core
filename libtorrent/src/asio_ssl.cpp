// builds all boost.asio SSL source as a separate compilation unit
#include <boost/version.hpp>

#ifdef __ANDROID__
#define OPENSSL_NO_ENGINE 1
#endif

#if BOOST_VERSION >= 104610
#include <boost/asio/ssl/impl/src.hpp>
#endif

