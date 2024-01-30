#!/bin/bash

set -euo pipefail

function usage {
    echo "usage:
    tc.sh off                                      # disable network restrictions
    tc.sh set <bandwidth in Mbit> <latency in ms>  # restrict bandwidth and latency"
}

HOST="$(uname -n)"

INTERFACE="lo"

if [[ $# -lt 1 ]] || [[ -z $1 ]]; then
    usage
    exit 1
fi

OPERATION="$1"

if [[ "$OPERATION" == "off" ]]; then

    /sbin/tc qdisc del dev "${INTERFACE}" root || true

elif [[ "$OPERATION" == "set" ]]; then
    if [[ $# -lt 3 ]] || [[ -z $2 || -z $3 ]]; then
        usage
        exit 1
    fi

    BANDWIDTH="$2"
    LATENCY="$3"

    # TODO: check that bandwidth and latency are numbers


    HALF_LATENCY="$(bc <<< "scale=2; (${LATENCY})/2")"

    /sbin/tc qdisc del dev ${INTERFACE} root || true
    /sbin/tc qdisc add dev ${INTERFACE} root handle 1:0 htb default 10
    /sbin/tc class add dev ${INTERFACE} parent 1:0 classid 1:10 htb rate "${BANDWIDTH}Mbit"
    /sbin/tc qdisc add dev ${INTERFACE} parent 1:10 handle 10:0 netem delay "${HALF_LATENCY}ms"

else

    usage
    exit 1

fi

