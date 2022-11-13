// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Benson Muite
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include <stdio.h>

#define MESSAGE_LEN 32
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_BYTES 64

int main(void) {

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char message[MESSAGE_LEN];
    unsigned long long message_len = MESSAGE_LEN;
    unsigned char signature[crypto_sign_BYTES];
    unsigned long long signature_len = crypto_sign_BYTES;

    FILE *fp;
    int number_of_test_vectors = 0;
    char buff[255];
    int pos;

    fp = fopen("../../cases.txt", "r+");
    fscanf(fp, "%i", &number_of_test_vectors);
    printf("Number of test vectors: %i\n", number_of_test_vectors);
    printf("\n|Monocypher     |");
    for (int i = 0; i < number_of_test_vectors; i++) {
      // reading the message
      fscanf(fp, "%s", buff);
      pos = 0;
      for (size_t count = 0; count < 32; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &message[count]);
        pos += 2;
      }

      // reading the public key
      fscanf(fp, "%s", buff); // message 32 bytes
      pos = 0;
      for (size_t count = 0; count < 32; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &public_key[count]);
        pos += 2;
      }

      // reading the signature
      fscanf(fp, "%s", buff);
      pos = 0;
      for (size_t count = 0; count < 64; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &signature[count]);
        pos += 2;
      }
 
      int result = crypto_ed25519_check(signature, public_key, &message, message_len);
 
      if (result != 0) {
        printf(" X |");
        // Incorrect signature! 
      } else {
        printf(" V |");
      }
 
    }
 
    printf("\n");
    fclose(fp);
    return 0;
}
