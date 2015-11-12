#
# Dockerfile for building Twister peer-to-peer micro-blogging
#
FROM ubuntu:14.04

# Install twister-core
RUN apt-get update
RUN apt-get install -y git autoconf libtool build-essential libboost-all-dev libssl-dev libdb++-dev libminiupnpc-dev && apt-get clean
#RUN git clone https://github.com/miguelfreitas/twister-core.git
ADD . /twister-core
RUN cd twister-core && \
    ./bootstrap.sh && \
    make

# Install twister-html
RUN git clone https://github.com/miguelfreitas/twister-html.git /twister-html

# Configure HOME directory
# and persist twister data directory as a volume
ENV HOME /root
VOLUME /root/.twister

# Run twisterd by default
ENTRYPOINT ["/twister-core/docker-entrypoint.sh"]
EXPOSE 28332
