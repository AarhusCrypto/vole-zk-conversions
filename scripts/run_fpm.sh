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
    if [[ -z $1 || -z $2 || -z $3 || -z $4 || -z $5 ]]; then
        echo "usage: bench <protocol> <integer-size> <fraction-size> <num> <network setting>"
        exit 1
    fi

    protocol="$1"
    integer_size="$2"
    fraction_size="$3"
    num="$4"
    network_setting="$5"
    output_file_name="fpm__party=${PARTY}_protocol=${protocol}__integer-size=${integer_size}__fraction-size=${fraction_size}__num=${num}__network=${network_setting}__time=$(date --iso-8601=ns).json"

    time -p ../target/release/examples/bench \
        fpm \
        --party "${PARTY}" \
        ${CONNECT_OPT} \
        --protocol "${protocol}" \
        --num "${num}" \
        --integer-size "${integer_size}" \
        --fraction-size "${fraction_size}" \
        --repetitions "${REPETITIONS}" \
        --json \
    | tee "results/${output_file_name}"
}

# NB: for fpm, v1/v2 does not matter, and edabits needs to verify at least 1024 fpms
PROTOCOLS=`echo edabits cheddabits-v1-{tspa,xor4maj7}`
PROTOCOLS_NO_EDABITS=`echo cheddabits-v1-{tspa,xor4maj7}`
INTEGER_SIZES="30"
FRACTION_SIZES="15"
# NUMS="256 4096 65536 1048576" # 2^8, 2^12, 2^16, 2^20
NUMS="1024 4096 65536 1048576" # 2^10, 2^12, 2^16, 2^20
REPETITIONS=3 # set this to the number of repetitions you like.


# LAN

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh off
    sudo -A ./tc.sh set 11000 0.2
fi

for num in 256; do
    for integer_size in $INTEGER_SIZES; do
        for fraction_size in $FRACTION_SIZES; do
            for protocol in $PROTOCOLS_NO_EDABITS; do
                bench "${protocol}" "${integer_size}" "${fraction_size}" "${num}" lan
            done
        done
    done
done
for num in $NUMS; do
    for integer_size in $INTEGER_SIZES; do
        for fraction_size in $FRACTION_SIZES; do
            for protocol in $PROTOCOLS; do
                bench "${protocol}" "${integer_size}" "${fraction_size}" "${num}" lan
            done
        done
    done
done

# WAN

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh set 20 100
fi


for num in 256; do
    for integer_size in $INTEGER_SIZES; do
        for fraction_size in $FRACTION_SIZES; do
            for protocol in $PROTOCOLS_NO_EDABITS; do
                bench "${protocol}" "${integer_size}" "${fraction_size}" "${num}" wan
            done
        done
    done
done
for num in $NUMS; do
    for integer_size in $INTEGER_SIZES; do
        for fraction_size in $FRACTION_SIZES; do
            for protocol in $PROTOCOLS; do
                bench "${protocol}" "${integer_size}" "${fraction_size}" "${num}" wan
            done
        done
    done
done

if [[ "${PARTY}" == "prover" ]]; then
    sudo -A ./tc.sh off
fi
