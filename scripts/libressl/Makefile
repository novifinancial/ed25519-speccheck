LIBRESSL_INSTALL_DIR=./libressl-install
main: main.c
	g++ -o main main.c -I$(LIBRESSL_INSTALL_DIR)/include -L$(LIBRESSL_INSTALL_DIR)/lib -lcrypto -lssl -ltls

