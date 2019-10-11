#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

typedef struct cipher_file{
    FILE* file;
    EVP_CIPHER_CTX* cipher_ctx;
    int type;
}CIPHER_FILE;

CIPHER_FILE* cipher_open(const char* filename, const char* mode, const char* key) {
    CIPHER_FILE* cipher_file = NULL;
    FILE* file = NULL;
    EVP_CIPHER_CTX* cipher_ctx = NULL;

    

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (0 == strcmp(mode, "wb")) {
        EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, key + 16);
    } else if (0 == strcmp(mode, "rb")) {
        EVP_decryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, key + 16);
    } else {
        printf("unsupported mode\n");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return NULL;
    }

    file = fopen(filename, mode);
    cipher_file = (CIPHER_FILE*)malloc(sizeof(CIPHER_FILE));
    cipher_file->file = file;
    cipher_file->cipher_ctx = cipher_ctx;
    cipher_file->type = -1;
    return cipher_file;
}

int cipher_write(unsigned char* buffer, int size, CIPHER_FILE* file) {
    char* cipher_buffer[4112];
    int current_size = 4096;
    int offset = 0;
    int writed_size = 0;
    int len;
    while(size > 0) {
        if (size < 4096) {
            current_size = size;
        }
        if (1 != EVP_EncryptUpdate(file->cipher_ctx, cipher_buffer, &len, buffer, current_size)) {
            printf("error encrypt\n");
            return 0;
        }
        if ( len != fwrite(cipher_buffer, 1, len, file->file)){
            printf("write error\n");
            return 0;
        }
        size -= current_size;
        buffer += current_size;
        writed_size += len;
    }
    return writed_size;
}

