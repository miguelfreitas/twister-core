gcc -o test_dht test_dht.cpp -I../include/ -DBOOST_ASIO_SEPARATE_COMPILATION -lboost_system -lssl -lpthread .libs/libtest.a ../src/.libs/libtorrent-rasterbar.a -lrt
