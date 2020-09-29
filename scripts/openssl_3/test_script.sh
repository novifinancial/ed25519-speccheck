#!/bin/bash

export OPENSSL_PATH=./openssl-build

gcc -o main main.c -L"$OPENSSL_PATH"/lib -lssl -lcrypto -I"$OPENSSL_PATH"/include
./main
