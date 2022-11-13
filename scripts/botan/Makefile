LIBBOTAN_INSTALL_DIR=$(pwd)/libbotan-build
main: main.o
	g++ -o main main.o -L$(LIBBOTAN_INSTALL_DIR)/lib64 -lbotan-2

main.o: main.cpp
	g++ -c -I$(LIBBOTAN_INSTALL_DIR)/include/botan-2 main.cpp -o main.o
