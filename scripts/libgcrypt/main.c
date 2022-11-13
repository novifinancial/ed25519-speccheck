// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) Benson Muite
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

#include <gcrypt.h>
#include <stdio.h>
#include <errno.h>

#define MESSAGE_LEN 32
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_BYTES 64
int main(void) {

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char message[MESSAGE_LEN];
    unsigned long long message_len = MESSAGE_LEN;
    unsigned char sig_r[crypto_sign_BYTES/2];
    unsigned char sig_s[crypto_sign_BYTES/2];
    unsigned long long signature_len = crypto_sign_BYTES;
    gpg_error_t err;

    FILE *fp;
    int number_of_test_vectors = 0;
    char buff[255];
    int pos;
    int res;

    if (!gcry_check_version(GCRYPT_VERSION))
    {
      fputs("libgcrypt version mismatch\n", stderr);
      exit(2);
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs("libgcrypt has not been initialized\n", stderr);
        abort();
    }

    fp = fopen("../../cases.txt", "r+");
    fscanf(fp, "%i", &number_of_test_vectors);
    // printf("Number of test vectors: %i\n", number_of_test_vectors);
    printf("\n|Libgcyrpt      |");
    for (int i = 0; i < number_of_test_vectors; i++) {
      gcry_sexp_t s_pk = NULL;
      gcry_sexp_t s_msg= NULL;
      gcry_sexp_t s_sig= NULL;
      
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
      for (size_t count = 0; count < 32; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &sig_r[count]);
        pos += 2;
      }
      for (size_t count = 0; count < 32; count++) {
        sscanf(buff + 4 + pos, "%2hhx", &sig_s[count]);
        pos += 2;
      }

      err = gcry_sexp_build (&s_sig, NULL,
		      "(sig-val"
		      " (eddsa"
		      "  (r %b)"
		      "  (s %b)))",
		      (int)sizeof(sig_r), sig_r,
		      (int)sizeof(sig_s), sig_s);

      err = gcry_sexp_build (&s_pk, NULL,
                              "(public-key"
                              " (ecc"
                              "  (curve \"Ed25519\")"
                              "  (flags eddsa)"
                              "  (q %b)))",  
			  (int)sizeof(pk), pk);
     if (err)
        printf ("gcry_sexp_build failed: %s\n", gpg_strerror (err));

     err = gcry_sexp_build (&s_msg, NULL, 
		     "(data"
		     " (flags eddsa)"
                     " (raw)"
                     " (value %b))",  
			      (int)sizeof(message), message);
     if (err)
        printf ("gcry_sexp_build failed: %s\n", gpg_strerror (err));

     gpg_error_t result = gcry_pk_verify (s_sig, s_msg, s_pk);
//      printf(" %s \n",gpg_strerror (result));
      if (result != 0) {
        printf(" X |");
        /* Incorrect signature! */
      } else {
        printf(" V |");
      }
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_pk);
      gcry_sexp_release (s_msg);
    }
    printf("\n");
    fclose(fp);

    return 0;
}
