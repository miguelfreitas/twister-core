#!/bin/bash
set -e

BRIDGE_IP=$(ip ro get 8.8.8.8 | grep -oP '(?<=via )([\d\.]+)')

exec /twister-core/twisterd -rpcuser=user -rpcpassword=pwd -rpcallowip=${BRIDGE_IP} -htmldir=/twister-html -printtoconsole -port=28333 $*
