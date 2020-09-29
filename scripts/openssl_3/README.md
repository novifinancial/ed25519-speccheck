Tests against the latest version of OpenSSL from https://github.com/openssl/openssl (version: OpenSSL 3.0.0-alpha6-dev).

To reproduce:

clone the OpenSSL repo
run ./Configure, then make
fix the paths in test_script.sh to point to the local OpenSSL build
run ./test_script.sh

> git clone 