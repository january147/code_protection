#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY_CTX *ctx;
EVP_PKEY *pkey = NULL;

ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
if (!ctx)
 /* Error occurred */
if (EVP_PKEY_keygen_init(ctx) <= 0)
 /* Error */
if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
 /* Error */

/* Generate key */
if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
 /* Error */
