#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/stat.h>
//#define DEBUG

#define printBytesN(a,b) printBytes(a,b,NULL)
#define handleErrors() handleErrorsP("")


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

void handleErrorsP(const char* prompt)
{
    ERR_print_errors_fp(stderr);
    puts(prompt);
    exit(1);
}

void encrypt(const char* input_file, const char* out_put_file)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    char password[10];
    char salt[PKCS5_SALT_LEN];
    char key_iv[48];
    // output buffer should be a block size longer thant input buffer
    char plain_buffer[4096];
    char cipher_buffer[4112];
    FILE* plain_file = NULL;
    FILE* cipher_file = NULL;
    int imm_len;

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
    RAND_bytes(salt, sizeof(salt));
    #ifdef DEBUG
    printBytes(salt, sizeof(salt), "The salt is");
    #endif
    
    // generate key and iv
    if (0 == PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                                       1000, EVP_sha256(), sizeof(key_iv), key_iv)) {
            handleErrors();
    }
    
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

    plain_file = fopen(input_file, "rb");
    cipher_file = fopen(out_put_file, "wb");
    if (plain_file == NULL) {
        printf("file open error\n");
        exit(1);
    }
    if(8 != (len = fwrite(salt, 1, 8, cipher_file))) {
        printf("error write file, size %d\n", len);
        exit(1);
    }

    while ((imm_len = fread(plain_buffer, 1, 4096, plain_file)) != 0) {
        if(1 != EVP_EncryptUpdate(ctx, cipher_buffer, &len, plain_buffer, imm_len)) {
            handleErrors();
        }
#ifdef DEBUG
        printf("imm_len %d\n", imm_len);
        printf("cipher_len:%d\n", len);
#endif
        if(len != fwrite(cipher_buffer, 1, len, cipher_file)) {
            printf("file write error\n");
            exit(0);
        }
    }

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, cipher_buffer, &len))
        handleErrors();
    if(len != fwrite(cipher_buffer, 1, len, cipher_file)) {
            printf("file write error\n");
            exit(0);
        }
#ifdef DEBUG
    printf("cipher final:%d\n", len);
#endif

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plain_buffer, 4096);
    OPENSSL_cleanse(password, 10);
    fclose(cipher_file);
    fclose(plain_file);
}

int decrypt(const char* input_file, const char* output_file)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    char password[10];
    char salt[PKCS5_SALT_LEN];
    char key_iv[48];
    // output buffer should be a block size longer thant input buffer
    char plain_buffer[4112];
    char cipher_buffer[4096];
    FILE* plain_file = NULL;
    FILE* cipher_file = NULL;
    int imm_len;

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


    plain_file = fopen(output_file, "wb");
    cipher_file = fopen(input_file, "rb");
    if (plain_file == NULL || cipher_file == NULL) {
        printf("file open error\n");
        exit(1);
    }
    if(8 != (len = fread(salt, 1, 8, cipher_file))) {
        printf("error write file, size %d\n", len);
        exit(1);
    }

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

    while(0 != (imm_len = fread(cipher_buffer, 1, 4096, cipher_file))) {
        if(1 != EVP_DecryptUpdate(ctx, plain_buffer, &len, cipher_buffer, imm_len)) {
            handleErrorsP("error decrypt, maybe password not corret, or the file is corrupted");
        }
#ifdef DEBUG
        printf("imm_len %d\n", imm_len);
        printf("plain_len %d\n", len);
#endif
        fwrite(plain_buffer, 1, len, plain_file);
    }

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plain_buffer, &len)) {
        handleErrorsP("error decrypt, maybe password not corret, or the file is corrupted");
    }
#ifdef DEBUG
    printf("plain_final %d\n", len);
#endif
    fwrite(plain_buffer, 1, len, plain_file);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plain_buffer, 4096);
    OPENSSL_cleanse(password, 10);
    fclose(plain_file);
    fclose(cipher_file);
}

void file_test() {
    encrypt("plain.txt", "cipher.txt");
    decrypt("cipher.txt", "new_plain.txt");
}

void programm_test(int argc, char* argv[]) {
    int pid;
#ifdef DEBUG
    printf("argc %d\n", argc);
#endif
    if(argc < 3) {
        exit(0);
    }
    
    if (0 == strcmp(argv[1], "en")) {
        encrypt(argv[2], "encrypt_code");
    }

    if (0 == strcmp(argv[1], "run")) {
        decrypt(argv[2], ".decrypt_code");
        chmod(".decrypt_code", 00700);
        pid = fork();
        if(0 == pid) {
             if ( -1 == execl(".decrypt_code", ".decrypt_code", NULL)) {
                perror("execute failed");
            }
        } else {
            wait(NULL);
            remove(".decrypt_code");

        }       
    }
}

int main(int argc, char* argv[]){
    programm_test(argc, argv);
    return 0;
}
