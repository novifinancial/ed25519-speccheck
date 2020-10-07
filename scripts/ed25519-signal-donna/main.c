// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

int crypto_sign_open_modified(
  unsigned char *m,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
  );

#include "libsignal-protocol-c/src/curve25519/curve25519-donna.h"
#include "libsignal-protocol-c/src/curve25519/ed25519/tests/internal_fast_tests.h"

void hex_string_to_byte_array(char *buff, int buf_len, unsigned char *res) {
    char *pos = buff;

    for (int i = 0; i < buf_len; i++) {
        sscanf(pos, "%2hhx", &res[i]);
        pos += 2;
    }
}

void pprint(unsigned char buf[32]) {
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int curvesigs_cofac(int silent)
{
    int num_test_vectors = 0;

    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char msg[32];
    unsigned char verifybuf[32+64];
    unsigned char verifybuf2[32+64];


    FILE *fp;
    char buff[255];
    fp = fopen("../../../cases.txt", "r");
    fscanf(fp, "%i", &num_test_vectors);
    printf("\n|ed25519-donna  |");

    for (int i = 0; i < num_test_vectors; i++) {
        memset(pubkey, 0, 32);
        memset(signature, 0, 64);
        memset(msg, 0, 32);
        memset(verifybuf, 0, 32+64);
        memset(verifybuf2, 0, 32+64);

        fscanf(fp, "%s", buff);
        hex_string_to_byte_array(buff + 4, 32, msg);
        fscanf(fp, "%s", buff);
        hex_string_to_byte_array(buff + 4, 32, pubkey);
        fscanf(fp, "%s", buff);
        hex_string_to_byte_array(buff + 4, 64, signature);
//      printf("msg:")
//      pprint(msg);
//      printf("Verification:");

        /* Then perform a normal Ed25519 verification, return 0 on success */
        /* The below call has a strange API: */
        /* verifybuf = R || S || message */
        /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets
           replaced with pubkey for hashing */
        memmove(verifybuf, signature, 64);
        memmove(verifybuf+64, msg, 32);
        if (crypto_sign_open_modified(verifybuf2, verifybuf, 64 + 32, pubkey) == 0) {
          printf(" V |");
        } else {
          printf(" X |");
        }
    }
    printf("\n");
    return 0;
}
int main(void) {
    curvesigs_cofac(0);
}
