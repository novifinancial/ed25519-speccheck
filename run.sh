#!/bin/bash
#
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the APACHE 2.0 license found in
# the LICENSE file in the root directory of this source tree.

SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

main() {

cd "$SOURCE_DIR"
# Dalek, Zebra, BoringSSL, libra-crypto
cargo test -- --nocapture --test-threads 1

# CryptoKit
pushd "$SOURCE_DIR/scripts/ed25519-ios"
swift Ed25519.swift
popd

# ed25519-java, BouncyCastle
if [[ -z "$JAVA_HOME" ]]
then
    >&2 echo "Error running scripts/ed25519-java: JAVA_HOME is not set"
else

pushd "$SOURCE_DIR/scripts/ed25519-java"
JAVA_LIBS="$HOME"/.m2/repository
CLASSPATH=\
"$JAVA_HOME"/jre/lib/*:\
"$JAVA_HOME"/jre/lib/ext/*:\
"$JAVA_LIBS"/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar:\
"$JAVA_LIBS"/org/bouncycastle/bcprov-jdk15on/1.66/bcprov-jdk15on-1.66.jar:\
"$JAVA_LIBS"/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar

javac -cp $CLASSPATH src/main/java/*.java
java -cp $CLASSPATH:src/main/java TestVectorChecker
popd
fi

# ed25519-donna
pushd "$SOURCE_DIR/scripts/ed25519-signal-donna/build"
cmake ..
make
./test-donna
popd

# Go
go run scripts/go/main.go

# npm
NODE=$(which node)
pushd "$SOURCE_DIR/scripts/npm"
$NODE eddsa_test.js
popd

# tweetnacl-js
$NODE scripts/tweetnacl-js/test.js

# python-ed25519
pushd "$SOURCE_DIR/scripts/python-ed25519"
if [ ! -d "./python-ed25519" ]
then
    git clone git@github.com:warner/python-ed25519.git
    cd python-ed25519
    git reset --hard d57b8f2c7edffff3419d58443ccc29a4fa399a71
    git apply -v ../add_test_git.patch
    python3.7 setup.py build
else
    cd "./python-ed25519"
fi
python3.7 setup.py test
popd

# PyCA
python3.7 scripts/pyca-openssl/eddsa_utils.py

# LibSodium
pushd "$SOURCE_DIR/scripts/libsodium"
export LIBSODIUM_INSTALL_DIR=$(pwd)/libsodium-stable-build
echo $LIBSODIUM_INSTALL_DIR
if [ ! -d "libsodium-stable-build" ]
then
    wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    tar -xf libsodium-1.0.18-stable.tar.gz
    rm libsodium-1.0.18-stable.tar.gz
    mkdir libsodium-stable-build
    cd "./libsodium-stable/"
    ./configure --prefix="$LIBSODIUM_INSTALL_DIR"
    make & make check
    make install
    cd ..
fi
rm main
make
./main
popd

# ref10
pushd "$SOURCE_DIR/scripts/ref10"
export LIBSODIUM_INSTALL_DIR=$(pwd)/libsodium-stable-build
if [ ! -d "libsodium-stable-build" ]
then
    wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    tar -xf libsodium-1.0.18-stable.tar.gz
    rm libsodium-1.0.18-stable.tar.gz
    mkdir libsodium-stable-build
    patch -p0 < to_ref10.patch
    cd "./libsodium-stable/"
    ./configure --prefix="$LIBSODIUM_INSTALL_DIR"
    make & make check
    make install
    cd ..
fi
rm main
make
./main
popd

# openssl-3.0
pushd "$SOURCE_DIR/scripts/openssl_3"
export OPENSSL_INSTALL_DIR=$(pwd)/openssl-build
if [ ! -d "openssl" ]
then
    git clone git@github.com:openssl/openssl.git
    mkdir openssl-build
    cd "./openssl"
    git reset --hard 10203a34725ec75136b03d64fd2126b321419ac1
    ./Configure --prefix="$OPENSSL_INSTALL_DIR"
    make install
    cd ..
fi

./test_script.sh
popd

# zig
if command -v zig &> /dev/null; then
  pushd "$SOURCE_DIR/scripts/zig"
  zig build run < ../../cases.txt
  popd
fi
}

main > results.md  2>/dev/null

sed -ire  '/^|/!d' results.md
sort -f results.md -o results.md

cat results.md
