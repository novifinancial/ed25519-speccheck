[Libressl](https://www.libressl.org/) is available under a combination
of several licenses, including ISC, OpenSSL, SSLeay  and public domain.
Examine the source files to determine the ones that are appropriate.

At present ED25519 support is not enabled by default. A patch is applied
to enable it.

```
> wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.6.1.tar.gz
> tar -xf libressl-3.6.1.tar.gz
> export LIBRESSL_INSTALL_DIR=$(pwd)/libressl-install
> patch -p0 < try_ed25519.patch
> cd libressl-3.6.1
> ./configure --prefix=$(LIBRESSL_INSTALL_DIR)
> make
> make check
> make install
> cd ..
> make
> export LD_LIBRARY_PATH=$(LIBRESSL_INSTALL_DIR)/lib:$LD_LIBRARY_PATH
> ./main
```
