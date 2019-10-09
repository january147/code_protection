#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int generate_rsa_key(EVP_PKEY **key_out){
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
    /* Error occurred */
        handleErrors();
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0){
    /* Error */
       handleErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
    /* Error */
        handleErrors();
    }
    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &key) <= 0){
    /* Error */
        handleErrors();
    }

    BIO *bp = BIO_new(BIO_s_file());
    BIO_write_filename(bp, "publickey.rsa");
    PEM_write_bio_PUBKEY(bp, key);
    BIO_free_all(bp);

    bp = BIO_new_file("privatekey.rsa","wb");
    PEM_write_bio_PrivateKey(bp, key, NULL, NULL, 0, NULL, NULL);
    BIO_free_all(bp);

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    
}

int main(){
    EVP_PKEY* key;
    generate_rsa_key(&key);
    return 0;
}