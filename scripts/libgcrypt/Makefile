LIBGCRYPT_INSTALL_DIR=./libgcrypt-install
LIBPTH_INSTALL_DIR=./libpth-install
LIBGPG_ERROR_INSTALL_DIR=./libgpg-error-install
main: main.c
	gcc -o main main.c -I$(LIBGCRYPT_INSTALL_DIR)/include -L$(LIBGCRYPT_INSTALL_DIR)/lib -lgcrypt -L$(LIBGPG_ERROR_INSTALL_DIR)/lib -lgpg-error -L$(LIBPTH_INSTALL_DIR)/lib -lpth
