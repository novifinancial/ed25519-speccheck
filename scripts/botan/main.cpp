// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Benson Muite
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include <botan/sodium.h>
#include <stdio.h>

#define MESSAGE_LEN 32

using namespace Botan::Sodium;
int main(void) {
    if (sodium_init() < 0) {
      /* panic! the library couldn't be initialized, it is not safe to use */
      printf("PANIC \n");
      return 0;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char message[MESSAGE_LEN];
    uint8_t message_len = MESSAGE_LEN;
    unsigned char signature[crypto_sign_BYTES];

    FILE *fp;
    int number_of_test_vectors = 0;
    char buff[255];
    int pos;

    fp = fopen("../../cases.txt", "r+");
    fscanf(fp, "%i", &number_of_test_vectors);
    // printf("Number of test vectors: %i\n", number_of_test_vectors);
    printf("\n|Botan          |");
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
        sscanf(buff + 4 + pos, "%2hhx", &pk[count]);
        pos += 2;
      }

      // reading the signature
      fscanf(fp, "%s", buff);
      pos = 0;
      for (size_t count = 0; count < 64; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &signature[count]);
        pos += 2;
      }

      int result = crypto_sign_ed25519_verify_detached(signature, message, message_len, pk);
      
      if (result == -1) {
        printf(" X |");
        /* Incorrect signature! */
      } else {
        printf(" V |");
      }
    }
    printf("\n");
    fclose(fp);
    return 0;
}
