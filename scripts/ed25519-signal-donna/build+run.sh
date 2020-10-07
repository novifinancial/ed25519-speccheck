#!/bin/sh
#
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the APACHE 2.0 license found in
# the LICENSE file in the root directory of this source tree.
#
git clone https://github.com/signalapp/libsignal-protocol-c.git
mkdir build
cd build
cmake ..
make
cp ../test_vector.txt .
./test-donna
cd ..
