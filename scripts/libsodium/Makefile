LIBSODIUM_INSTALL_DIR=./libsodium-stable-build
main: main.c
	gcc -o main main.c -I$(LIBSODIUM_INSTALL_DIR)/include -L$(LIBSODIUM_INSTALL_DIR)/lib -lsodium
