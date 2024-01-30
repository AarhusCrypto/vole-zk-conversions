#!/bin/bash

set -euxo pipefail

echo "enter password:"
read -s PASSWD
export PASSWD
export SUDO_ASKPASS=./asker.sh


PARTY="$1"

if [[ "${PARTY}" == "prover" ]]; then
    CONNECT_OPT="--listen"
elif [[ "${PARTY}" == "verifier" ]]; then
    CONNECT_OPT=""
else
    echo "unknown party: '${PARTY}'"
    exit 1
fi


function bench {
    if [[ -z $1 || -z $2 || -z $3 || -z $4 ]]; then
        echo "usage: bench <protocol> <bit-size> <num> <network setting>"
        exit 1
    fi

    protocol="$1"
    bit_size="$2"
    num="$3"
    network_setting="$4"
    output_file_name="ched__party=${PARTY}_protocol=${protocol}__bit-size=${bit_size}__num=${num}__network=${network_setting}__time=$(date --iso-8601=ns).json"

    time -p ../target/release/examples/bench \
        conv \
        --party "${PARTY}" \
        ${CONNECT_OPT} \
        --protocol "${protocol}" \
        --num "${num}" \
        --bit-size "${bit_size}" \
        --repetitions "${REPETITIONS}" \
        --json \
    | tee "results/${output_file_name}"
}

# NB: edabits needs to verify at least 1024 convs
PROTOCOLS=`echo edabits cheddabits-{v1,v2}-{tspa,xor4maj7}`
PROTOCOLS_NO_EDABITS=`echo cheddabits-{v1,v2}-{tspa,xor4maj7}`
BIT_SIZES="8 16 32 60"
# NUMS="256 4096 65536 1048576" # 2^8, 2^12, 2^16, 2^20
NUMS="1024 4096 65536 1048576" # 2^10, 2^12, 2^16, 2^20
REPETITIONS=3


# LAN

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh off
    sudo -A ./tc.sh set 11000 0.2
fi

for num in 256; do
    for bit_size in $BIT_SIZES; do
        for protocol in $PROTOCOLS_NO_EDABITS; do
            bench "${protocol}" "${bit_size}" "${num}" lan
        done
    done
done
for bit_size in $BIT_SIZES; do
    for num in $NUMS; do
        for protocol in $PROTOCOLS; do
            bench "${protocol}" "${bit_size}" "${num}" lan
        done
    done
done

# WAN

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh set 20 100
fi

for num in 256; do
    for bit_size in $BIT_SIZES; do
        for protocol in $PROTOCOLS_NO_EDABITS; do
            bench "${protocol}" "${bit_size}" "${num}" wan
        done
    done
done
for bit_size in $BIT_SIZES; do
    for num in $NUMS; do
        for protocol in $PROTOCOLS; do
            bench "${protocol}" "${bit_size}" "${num}" wan
        done
    done
done

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh off
fi
