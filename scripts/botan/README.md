[Botan](https://botan.randombit.net) is available under a BSD-2-Clause license

```
> wget https://botan.randombit.net/releases/Botan-2.19.2.tar.xz
> tar -xf Botan-2.19.2.tar.xz
> mkdir libbotan-build
> export LIBBOTAN_INSTALL_DIR=$(pwd)/libbotan-build
> cd Botan-2.19.2
> ./configure --prefix=$(LIBBOTAN_INSTALL_DIR)
> make
> make check
> make install
> cd ..
> export LD_LIBRARY_PATH=$(pwd)/libbotan-build/lib64:$LD_LIBRARY_PATH
> make
> ./main
```
