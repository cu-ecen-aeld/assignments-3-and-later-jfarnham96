#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "ERROR - please specify 2 arguments. 1: writefile, 2: writedir"
    exit 1
fi

writefile=$1
writestr=$2

writedir=$(dirname "$writefile")

if ! mkdir -p "$writedir"; then
    echo "ERROR - couldn't create directory $writedir"
    exit 1
fi

if ! echo "$writestr" > "$writefile"; then
    echo "ERROR - couldn't create $writefile or couldn't write $writestr to $writefile"
    exit 1
fi

echo "Wrote $writestr to $writefile"
exit 0
