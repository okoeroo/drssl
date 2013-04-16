#!/bin/bash


if [ -z $1 ]; then
    echo "Give one argument, the host/target"
    exit 1
else
    HOST=$1
fi


calldrssl() {
    CIPHER=$1
    HOST=$2

    echo $CIPHER
    ./drssl --cipherlist $CIPHER --host $HOST  >/dev/null 2>&1
    RC=$?
    if [ $RC -eq 0 ]; then
        echo "-------------- The cipher $CIPHER was usable on $HOST -------------"
    fi

}


SUITE="COMPLEMENTOFDEFAULT"
echo ".....$SUITE......"
openssl ciphers -v "$SUITE" | cut -d" " -f 1 | while read CIPHER; do
    calldrssl $CIPHER $HOST
done

SUITE="HIGH"
echo ".....$SUITE......"
openssl ciphers -v "$SUITE" | cut -d" " -f 1 | while read CIPHER; do
    calldrssl $CIPHER $HOST
done

SUITE="MEDIUM"
echo ".....$SUITE......"
openssl ciphers -v "$SUITE" | cut -d" " -f 1 | while read CIPHER; do
    calldrssl $CIPHER $HOST
done

SUITE="LOW"
echo ".....$SUITE......"
openssl ciphers -v "$SUITE" | cut -d" " -f 1 | while read CIPHER; do
    calldrssl $CIPHER $HOST
done

SUITE="COMPLEMENTOFALL"
echo ".....$SUITE......"
openssl ciphers -v "$SUITE" | cut -d" " -f 1 | while read CIPHER; do
    calldrssl $CIPHER $HOST
done

