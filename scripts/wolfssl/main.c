// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Benson Muite
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define MESSAGE_LEN 32
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_BYTES 64

int main(int argc, char **argv) {
  int num_test_vectors = 0;
  FILE *fp;
  char buff[255];
  byte pk[crypto_sign_PUBLICKEYBYTES];
  byte message[MESSAGE_LEN];
  unsigned long long message_len = MESSAGE_LEN;
  byte signature[crypto_sign_BYTES];

  ed25519_key ed_pkey;
  byte pub[32];
  word32 pubSz = sizeof(pub);
  int ret;
  int verified;
  int pos;
  word32 sigSz = sizeof(signature);

  fp = fopen("../../cases.txt", "r");
  fscanf(fp, "%i", &num_test_vectors);
  printf("|WOLFSSL 5.5.3    |");
  for (int i = 0; i < num_test_vectors; i++) {
    // reading the message 32 bytes
    fscanf(fp, "%s", buff);
    pos = 0;
    for (size_t count = 0; count < 32; count++) {
      sscanf(buff + 4 + pos, "%2hhx", &message[count]);
      pos += 2;
    }

    // reading the public key 32 bytes
    fscanf(fp, "%s", buff); 
    pos = 0;
    for (size_t count = 0; count < 32; count++) {
      sscanf(buff + 4 + pos, "%2hhx", &pk[count]);
      pos += 2;
    }

    // reading the signature 64 bytes
    fscanf(fp, "%s", buff);
    pos = 0;
    for (size_t count = 0; count < 64; count++) {
      sscanf(buff + 4 + pos, "%2hhx", &signature[count]);
      pos += 2;
    }

    ret = wc_ed25519_init(&ed_pkey);
    if (ret !=0) {
      printf("Error initializing key\n");
      break;
    }

    ret = wc_ed25519_import_public(pk,sizeof(pk),&ed_pkey);
    if (ret != 0) {
      printf("Error importing public key\n");
      break;
    }

    verified = 0;
    ret = wc_ed25519_verify_msg(signature, sizeof(signature),
                                message, sizeof(message), 
				&verified, &ed_pkey);
    if (ret < 0 ) {
      printf(" E |");
    }else{ 
      printf(verified ? " V |" : " X |");
    }
    wc_ed25519_free(&ed_pkey);
  }
  printf("\n");
  fclose(fp);
  return 1;
}
