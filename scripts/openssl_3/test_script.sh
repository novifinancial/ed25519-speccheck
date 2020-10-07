#!/bin/bash

# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the APACHE 2.0 license found in
# the LICENSE file in the root directory of this source tree.

export OPENSSL_PATH=./openssl-build

gcc -o main main.c -L"$OPENSSL_PATH"/lib -lssl -lcrypto -I"$OPENSSL_PATH"/include
./main
