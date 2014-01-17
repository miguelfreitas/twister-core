#!/bin/bash

TWISTER_CORE_PATH='/home/vagrant/twister-core'
TWISTER_HOME='/home/vagrant/.twister'
AS_VAGRANT='sudo -u vagrant'

function failed {
	echo 
	echo 'Something failed !!!!!'
	echo
	exit 1
}
function checkfail {
	if [ ! $? -eq 0 ]; then
		failed
	fi
	sleep 3
}

echo
echo 'Running bootstrap for twister-core'
echo 
$AS_VAGRANT ln -s /vagrant $TWISTER_CORE_PATH


echo '.. fixing permissions'
cd $TWISTER_CORE_PATH
find $TWISTER_CORE_PATH/scripts -type d -exec chmod 755 {} \;
find $TWISTER_CORE_PATH/scripts -type f -exec chmod 644 {} \;
chmod 755 $TWISTER_CORE_PATH/scripts/bin/* 
apt-get update


echo '.. installing tools and libraries'
apt-get install -y git build-essential autoconf libtool libssl-dev libboost-all-dev libdb++-dev libminiupnpc-dev openssl 
checkfail


echo '.. bootstrapping libtorrent'
cd $TWISTER_CORE_PATH/libtorrent
$AS_VAGRANT ./bootstrap.sh
checkfail
$AS_VAGRANT ./configure --enable-logging --enable-debug --enable-dht
checkfail


echo '.. compiling'
cd $TWISTER_CORE_PATH/src
$AS_VAGRANT make -f makefile.unix
checkfail


echo '.. configuration & web gui'
$AS_VAGRANT mkdir $TWISTER_HOME
cd $TWISTER_HOME
$AS_VAGRANT touch twister.conf
echo -e "rpcuser=user\nrpcpassword=pwd\nrpcallowip=127.0.0.1" > twister.conf
chmod 600 twister.conf
git clone https://github.com/miguelfreitas/twister-html.git html
checkfail




if [ $? -eq 0 ]; then
  echo
  echo '=================================================================='
  echo "
Done. 
To start the web interface, enter the following command:
 $ vagrant ssh -c '$TWISTER_CORE_PATH/src/twisterd -daemon -debug'
Open http://127.0.0.1:28332/index.html and use the user/pwd credentials
Create your account !
  
If you want to do some development or other stuff then...
 $ vargrant ssh
 $ source twister-core/scripts/activate
 
 This will give you some nice to have commands like
 * twister start|stop   -  to start and stop the server
 * twisted              -  alias to ~/twisted-core/src/twisted
 
 Good luck!
 "
else
  failed

fi