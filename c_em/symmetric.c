#include<openssl/conf.h>
#include<openssl/evp.h>
#include <openssl/rand.h>
#include<openssl/err.h>
#include<string.h>
#define DEBUG

#define printBytesN(a,b) printBytes(a,b,NULL)

void printBytes(unsigned char* bytes, int len, const char* prompt){
    int i=0;

    if (prompt != NULL) {
        printf("%s:\n",prompt);
    }
    for(i=0; i<len; i++){
        printf("%02x ", *(bytes + i));
        if ((i + 1) % 10 == 0) {
            printf("\n");
        }
    }
    if( i % 10 != 0 ) {
        printf("\n");
    }
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    char password[10];
    char salt[PKCS5_SALT_LEN];
    char key_iv[48];
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    

    // read password
    for(;;){
        printf("please input your password\n");
        scanf("%10s", password);
        if(strlen(password) > 5){
            break;
        }
        printf("password too short, at least six letters.\n");
    }
    // generate salt
    printf("The salt is:\n");
    RAND_bytes(salt, sizeof(salt));
    #ifdef DEBUG
    printBytesN(salt, sizeof(salt));
    #endif
    
    // generate key and iv
    if (0 == PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                                       1000, EVP_sha256(), sizeof(key_iv), key_iv)) {
            handleErrors();
    }
    // put salt into ciphertext
    memcpy(ciphertext, salt, sizeof(salt));
    ciphertext = ciphertext + sizeof(salt);
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_iv, key_iv + 32))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len + sizeof(salt);
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    char password[10];
    char salt[PKCS5_SALT_LEN];
    char key_iv[48];
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    // read password
    for(;;){
        printf("please input your password\n");
        scanf("%10s", password);
        if(strlen(password) > 5){
            break;
        }
        printf("password too short, at least six letters");
    }

    // get salt from ciphertext
    memcpy(salt, ciphertext, sizeof(salt));
    ciphertext += sizeof(salt);
    ciphertext_len -= sizeof(salt);

    // generate key and iv
    if (0 == PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                                       1000, EVP_sha256(), sizeof(key_iv), key_iv)) {
            handleErrors();
    }

    #ifdef DEBUG
    printBytesN(salt, sizeof(salt));
    #endif

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_iv, key_iv + 32))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(){
    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext),
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, 
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);


    return 0;
}