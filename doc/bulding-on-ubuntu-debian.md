# Ubuntu / Debian building instructions

## Install

1. sudo apt-get update
1. sudo apt-get install build-essential libssl-dev libboost-all-dev libdb++-dev libminiupnpc-dev git openssl
1. git clone https://github.com/miguelfreitas/twister-core.git
1. cd twister-core/libtorrent
1. ./bootstrap.sh
1. ./configure --enable-logging --enable-debug --enable-dht
1. make
1. cd ../src
1. make -f makefile.unix

## Configuration & web gui

1. mkdir ~/.twister
1. echo -e "rpcuser=user\nrpcpassword=pwd" > ~/.twister/twister.conf
1. chmod 600 ~/.twister/twister.conf
1. git clone https://github.com/miguelfreitas/twister-html.git ~/.twister/html

## Start

1. cd twister-core/src
1. ./twisterd -rpcuser=user -rpcpassword=pwd
1. Open http://127.0.0.1:28332/index.html and use the user/pwd credentials
1. Create your account !
