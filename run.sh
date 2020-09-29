#!/bin/bash

{
# Dalek, Zebra, BoringSSL, libra-crypto
cargo test -- --nocapture --test-threads 1

# CryptoKit
cd scripts/ed25519-ios
swift Ed25519.swift
cd ../..

# ed25519-java, BouncyCastle
if [[ -z "$JAVA_HOME" ]]
then
    >&2 echo "Error running scripts/ed25519-java: JAVA_HOME is not set"
else

cd scripts/ed25519-java
JAVA_LIBS="$HOME"/.m2/repository
CLASSPATH=\
"$JAVA_HOME"/jre/lib/*:\
"$JAVA_HOME"/jre/lib/ext/*:\
"$JAVA_LIBS"/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar:\
"$JAVA_LIBS"/org/bouncycastle/bcprov-jdk15on/1.66/bcprov-jdk15on-1.66.jar:\
"$JAVA_LIBS"/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar

javac -cp $CLASSPATH src/main/java/*.java
java -cp $CLASSPATH:src/main/java TestVectorChecker
cd ../..

fi

# ed25519-donna
cd scripts/ed25519-signal-donna/build
cmake ..
make
./test-donna
cd ../../..

# Go
go run scripts/go/main.go

# npm
cd scripts/npm
/usr/local/bin/node eddsa_test.js
cd ../..

# tweetnacl-js
/usr/local/bin/node scripts/tweetnacl-js/test.js

# python-ed25519
cd scripts/python-ed25519
if [ ! -d "python-ed25519" ] 
then
    git clone git@github.com:warner/python-ed25519.git
    cd python-ed25519
    git reset --hard d57b8f2c7edffff3419d58443ccc29a4fa399a71
    git apply -v ../add_test_git.patch
    python3.7 setup.py build
else
    cd python-ed25519
fi
python3.7 setup.py test
cd ../../..

# PyCA
python3.7 scripts/pyca-openssl/eddsa_utils.py

# LibSodium
cd scripts/libsodium
export LIBSODIUM_INSTALL_DIR=$(pwd)/libsodium-stable-build
echo $LIBSODIUM_INSTALL_DIR
if [ ! -d "libsodium-stable-build" ] 
then
    wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    tar -xf libsodium-1.0.18-stable.tar.gz
    rm libsodium-1.0.18-stable.tar.gz
    mkdir libsodium-stable-build
    cd libsodium-stable/
    ./configure --prefix="$LIBSODIUM_INSTALL_DIR"
    make & make check
    make install
    cd ..
fi
rm main
make
./main
cd ../..

# ref10
cd scripts/ref10
export LIBSODIUM_INSTALL_DIR=$(pwd)/libsodium-stable-build
if [ ! -d "libsodium-stable-build" ] 
then
    wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    tar -xf libsodium-1.0.18-stable.tar.gz
    rm libsodium-1.0.18-stable.tar.gz
    mkdir libsodium-stable-build
    patch -p0 < to_ref10.patch
    cd libsodium-stable/
    ./configure --prefix="$LIBSODIUM_INSTALL_DIR"
    make & make check
    make install
    cd ..
fi
rm main
make
./main
cd ../..

# openssl-3.0
cd scripts/openssl_3
export OPENSSL_INSTALL_DIR=$(pwd)/openssl-build
if [ ! -d "openssl" ]
then
    git clone git@github.com:openssl/openssl.git
    mkdir openssl-build
    cd openssl
    git reset --hard 10203a34725ec75136b03d64fd2126b321419ac1
    ./Configure --prefix="$OPENSSL_INSTALL_DIR"
    make install
    cd ..
fi

./test_script.sh
cd ../..
} > results.md  2>/dev/null

sed -i '' '/^|/!d' results.md
sort -f results.md -o results.md

cat results.md
