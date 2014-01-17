# Ubuntu / Debian building instructions

## Install

1. sudo apt-get update
2. sudo apt-get install build-essential libssl-dev libboost-all-dev libdb++-dev libminiupnpc-dev git openssl
3. git clone https://github.com/miguelfreitas/twister-core.git
4. cd twister-core/libtorrent
5. ./bootstrap.sh --with-boost-libdir=/usr/lib/x86_64-linux-gnu
6. ./configure --enable-logging --enable-debug --enable-dht
7. make
8. sudo make install
9. cd ../src
10. make -f makefile.unix

## Configuration & web gui

1. mkdir ~/.twister
2. echo -e "rpcuser=user\nrpcpassword=pwd" > ~/.twister/twister.conf
3. chmod 600 ~/.twister/twister.conf
4. git clone https://github.com/miguelfreitas/twister-html.git ~/.twister/html

## Start

1. cd twister-core/src
2. ./twisterd -rpcuser=user -rpcpassword=pwd
3. Open http://127.0.0.1:28332/index.html and use the user/pwd credentials
4. Create your account !
