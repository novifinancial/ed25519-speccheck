> wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
> tar -xf libsodium-1.0.18-stable.tar.gz
> rm libsodium-1.0.18-stable.tar.gz
> mkdir libsodium-stable-build
> export LIBSODIUM_INSTALL_DIR=$(pwd)/libsodium-stable-build
> cd libsodium-stable/
> ./configure --prefix=$(LIBSODIUM_INSTALL_DIR)
> make & make check
> make install
