Ubuntu / Debian building instructions 
====================================

### Install:

1) sudo apt-get update

2) sudo apt-get install build-essential libssl-dev libboost-all-dev libdb4.8-dev libdb++-dev libminiupnpc-dev git openssl

3) git clone https://github.com/miguelfreitas/twister-core.git

4) cd twister-core 

5) cd libtorrent

6) ./bootstrap.sh

7) ./configure --enable-logging --enable-debug --enable-dht

8) make 'if you have multi-core CPU use -j N where n = cpu cores'

9) cd ../

10) cd src

11) make -f makefile.unix

### Configure & web gui:
1) 'echo -e "rpcuser=user\nrpcpassword=pwd" > "/home/${USER}/.twister/twister.conf"
chmod 600 "/home/${USER}/.twister/twister.conf"'

2) cd /home/${USER}/.twister/

3) git clone git@github.com:miguelfreitas/twister-html.git ./html

### Start
1) Go to src folder (on 10 step) 

2) ./twisterd -rpcuser=user -rpcpassword=pwd -rpcallowip=127.0.0.1

3) Open http://127.0.0.1:28332/home.html
