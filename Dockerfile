#
# Dockerfile for building Twister peer-to-peer micro-blogging
#

FROM		debian:testing
MAINTAINER	Álvaro Justen <alvarojusten@gmail.com>

ENV			DEBIAN_FRONTEND noninteractive

# Update repositories
RUN		echo 'deb http://http.debian.net/debian testing main contrib' > /etc/apt/sources.list
RUN		echo 'deb http://http.debian.net/debian testing-updates main contrib' >> /etc/apt/sources.list
RUN		echo 'deb http://security.debian.org testing/updates main contrib' >> /etc/apt/sources.list
RUN		apt-get update

# Install needed packages to build and run twisterd
RUN		apt-get -y install \
			git autoconf libtool build-essential \
			libboost-all-dev libdb++-dev libminiupnpc-dev libssl-dev

# Clean APT cache to save disk space
RUN		apt-get clean

# Download and build twister
RUN		mkdir /root/.twister
RUN		git clone https://github.com/miguelfreitas/twister-core.git /root/twister-core
RUN		git clone https://github.com/miguelfreitas/twister-html.git /root/.twister/html
RUN		cd /root/twister-core && ./bootstrap.sh
RUN		cd /root/twister-core && make

EXPOSE		28332
ENTRYPOINT	["/root/twister-core/twisterd"]
CMD			["-rpcuser=user", "-rpcpassword=pwd", "-rpcallowip=*", \
			 "-datadir=/root/.twister", "-htmldir=/root/.twister/html"]
