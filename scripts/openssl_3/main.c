#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/async.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/modes.h>

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

  fp = fopen("test_vector.txt", "r");
  fscanf(fp, "%i", &num_test_vectors);
  printf("number of test vectors: %i\n", num_test_vectors);
  for (int i = 0; i < num_test_vectors; i++) {
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 32, msg);
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 32, pk);
    fscanf(fp, "%s", buff);
    hex_string_to_byte_array(buff + 4, 64, sig);
  
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *ed_pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, pk, 32);
    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, ed_pkey);
    int result = EVP_DigestVerify(ctx, sig, 64, msg, 32);
    printf("%i: ", i);
    printf(result ? "true\n" : "false\n");
  }
  fclose(fp);
  return 1;
}
