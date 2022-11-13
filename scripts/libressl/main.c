// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Benson Muite
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "openssl/curve25519.h"
#include "openssl/sha.h"

void hex_string_to_byte_array(char *buff, int buf_len, unsigned char *res) {
  char *pos = buff;

  for (int i = 0; i < buf_len; i++) {
    sscanf(pos, "%2hhx", &res[i]);
    pos += 2;
  }
}

int main(int argc, char **argv) {
  int num_test_vectors = 0;

  FILE *fp;
  char buff[255];
  unsigned char msg[32];
  unsigned char pk[32];
  unsigned char sig[64];

  fp = fopen("../../cases.txt", "r");
  fscanf(fp, "%i", &num_test_vectors);
  printf("|LibreSSL-3.6.1   |");
  for (int i = 0; i < num_test_vectors; i++) {
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 32, msg);
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 32, pk);
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 64, sig);

    int result = ED25519_verify(msg, (size_t)sizeof(msg),
                   sig, pk);
    printf(result ? " V |" : " X |");
  }
  printf("\n");
  fclose(fp);
  return 1;
}
