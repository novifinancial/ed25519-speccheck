This is the source from https://github.com/signalapp/libsignal-protocol-c/tree/master/src/curve25519 as of commit 3a83a4f.

The test vectors must be in the same directory as your shell when you execute it and in a file named test_vector.txt

To run it:
```
git clone https://github.com/signalapp/libsignal-protocol-c.git
mkdir build 
cd build
cmake ..
make
cp ../test_vector.txt .
./test-donna
``` 
