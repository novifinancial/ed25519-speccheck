wolfSSL is available under GPLv2 license as well as under
commercial/custom licenses.

```
> wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.5.3-stable.tar.gz
> tar -xf v5.5.3-stable.tar.gz
> export LIBWOLFSSL_INSTALL_PATH=$(pwd)/wolfssl-install
> cd wolfssl-5.5.3-stable/
> ./autogen.sh 
> ./configure --prefix=$(LIBWOLFSSL_INSTALL_PATH) --enable-opensslextra --enable-opensslall --enable-curve25519 --enable-ed25519
> make
> make install
> cd ..
> export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIBWOLFSSL_INSTALL_PATH/lib
> make
> ./main
```
