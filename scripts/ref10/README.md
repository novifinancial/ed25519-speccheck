To reproduce the results download and install libsodium (see [https://doc.libsodium.org/installation](https://doc.libsodium.org/installation)):
* Download the latest stable tarball, untar to `libsodium_untared`
* Change the source code of `libsodium_untared` to use the old version, ref10 from SUPERCORP:
** Open file src/libsodium/crypto_sign/ed25519/ref10/sign_ed25519_ref10.h
** Add #define ED25519_COMPAT
** This makes the libsodium code most close to original ref10 see the history of file (libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c)[https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/open.c#L26]
* libsodium_untared> ./configure --prefix=$(LIBSODIUM_INSTALL_DIR)
* libsodium_untared> make & make check
* libsodium_untared> make install

Once libsodium installs, go to the Makefile of this directory, fix the variable LIBSODIUM_INSTALL_DIR as needed to match the one passed into ./configure.

Run make & ./main to get the results.

The output is:
0: false
1: true
2: false
3: true
4: false
5: true
6: false
7: true
8: false
9: true
10: false
11: false
12: false

(last reproduced in Aug 2020)