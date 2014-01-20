# Gentoo building instructions

## Install

1. sudo layman -o https://raw.github.com/ddorian1/gentoo-twister-overlay/master/gentoo-twister-overlay.xml -a twister
1. sudo emerge -av twister

## Configuration & web gui

1. mkdir ~/.twister
1. echo -e "rpcuser=user\nrpcpassword=pwd" > ~/.twister/twister.conf
1. chmod 600 ~/.twister/twister.conf
1. git clone https://github.com/miguelfreitas/twister-html.git ~/.twister/html

## Start

1. twisterd -rpcuser=user -rpcpassword=pwd
1. Open http://127.0.0.1:28332/index.html and use the user/pwd credentials
1. Create your account !
