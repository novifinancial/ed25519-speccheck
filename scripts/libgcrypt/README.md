[Libgcrypt](https://www.gnupg.org/software/libgcrypt/index.html) is 
available under LGPLv2.1+ with the documentation and some helper 
programs are available under GPLv2+.

[Libgpg-error](https://www.gnupg.org/software/libgpg-error/index.html)
is available under LGPLv2.1+

[Pth](https://www.gnupg.org/software/npth/index.html) is available under
LGPLv2.1+

Note that if some of these libraries are already installed on your system,
it may be easier to use them rather than update paths to a new installation.

```
> wget ftp://ftp.gnu.org/gnu/pth/pth-2.0.7.tar.gz
> tar -xf pth-2.0.7.tar.gz
> export PTH_INSTALL_DIR=$(pwd)/pth-install
> cd pth-2.0.7
> ./configure --prefix=$(PTH_INSTALL_DIR)
> make
> make check
> make install
> cd ..
> wget https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.46.tar.bz2
> tar -xf libgpg-error-1.46.tar.bz2
> export LIBGPG_ERROR_INSTALL_DIR=$(pwd)/libgpg-error-install
> cd libgpg-error-1.46/
> ./configure --prefix=$(LIBGPG_ERROR_INSTALL_DIR)
> make
> make check
> make install
> cd ..
> wget https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.10.1.tar.bz2
> tar -xf libgcrypt-1.10.1.tar.bz2
> export LIBGCRYPT_INSTALL_DIR=$(pwd)/libgcrypt-install
> cd libgcrypt-1.10.1/
> ./configure --prefix=$(LIBGCRYPT_INSTALL_DIR) --with-libgpg-error-prefix=$(LIBGPG_ERROR_INSTALL_DIR) --with-pth-prefix=$(PTH_INSTALL_DIR)
> make
> make check
> make install
> cd ..
> export LD_LIBRARY_PATH=$(LIBGPG_ERROR_INSTALL_DIR)/lib:$(PTH_INSTALL_DIR)/lib:$(LIBGCRYPT_INSTALL_DIR)/lib:$LD_LIBRARY_PATH
> make
> ./main
```
