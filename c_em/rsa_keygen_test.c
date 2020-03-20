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
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0){
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

    EVP_PKEY_CTX_free(ctx);
    *key_out = key;
    
}


int main(){
    EVP_PKEY* key = NULL;
    FILE* key_file;
    
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
    char* msg = "this is a message";
    char* sig = NULL;
    
    key_file = fopen("privatekey.rsa", "rb");
    key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);

    int slen;

    //generate_rsa_key(&key);
    
    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())) goto err;
    
    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto err;
    
    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) goto err;
    
    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
    if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) goto err;
    /* Allocate memory for the signature based on size in slen */
    sig = (char*)malloc(slen);
    printf("slen %d\n", slen);
    if (sig == NULL) {
        goto err;
    }
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, sig, &slen)) goto err;
    printf("slen %d\n", slen);
    BIO_dump_fp(stdout, sig, slen);
    /* Success */
    ret = 1;
    
    err:

    return 0;
}