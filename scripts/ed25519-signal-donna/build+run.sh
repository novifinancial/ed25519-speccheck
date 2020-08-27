#!/bin/sh
git clone https://github.com/signalapp/libsignal-protocol-c.git
mkdir build 
cd build
cmake ..
make
cp ../test_vector.txt .
./test-donna
cd ..
