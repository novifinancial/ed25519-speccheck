#!/bin/bash

OPENSSL_PATH=/Users/valerini/Research/EdDSA/openssl

gcc -o main main.c -L$OPENSSL_PATH -lssl -lcrypto -I$OPENSSL_PATH/include
./main
