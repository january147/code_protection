#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 16
#define ENCRYPT 1
#define DECRYPT 0

typedef struct cipher_file{
    FILE* file;
    EVP_CIPHER_CTX* cipher_ctx;
    int type;
}CIPHER_FILE;

CIPHER_FILE* cipher_open(const char* filename, const char* mode, const char* key) {
    CIPHER_FILE* cipher_file = NULL;
    FILE* file = NULL;
    EVP_CIPHER_CTX* cipher_ctx = NULL;

    
    file = fopen(filename, mode);
    cipher_file = (CIPHER_FILE*)malloc(sizeof(CIPHER_FILE));
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (0 == strcmp(mode, "wb")) {
        EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, key + 32);
        cipher_file->type = ENCRYPT;

    } else if (0 == strcmp(mode, "rb")) {
        EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, key + 32);
        cipher_file->type = DECRYPT;
    } else {
        printf("unsupported mode\n");
        EVP_CIPHER_CTX_free(cipher_ctx);
        free(file);
        fclose(file);
        return NULL;
    }

    cipher_file->file = file;
    cipher_file->cipher_ctx = cipher_ctx;
    return cipher_file;
}

int cipher_write(unsigned char* buffer, int size, CIPHER_FILE* file) {
    char cipher_buffer[4112];
    int current_size = 4096;
    int offset = 0;
    int writed_size = 0;
    int len;

    if (size & 0xf != 0) {
        printf("size must be the multiple of 16\n");
        return 0;
    }

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

int cipher_read(unsigned char* buffer, int size, CIPHER_FILE* file) {
    char cipher_buffer[4112];
    int current_size = 4096;
    int offset = 0;
    int readed_size = 0;
    int len;
    int end = 0;
    if (size & 0xf != 0) {
        printf("size must be the multiple of 16\n");
        return 0;
    }

    while((size > 0) && (end == 0)) {
        if (size < 4096) {
            current_size = size;
        }

        if ( 0 == (current_size = fread(cipher_buffer, 1, current_size, file->file) )){
            if (0 == feof(file->file)) {
                printf("read error\n");
            }
            return 0;
        } else {
            if (0 != feof(file->file)) {
                end = 1;
            }
        }
        if (1 != EVP_DecryptUpdate(file->cipher_ctx, buffer, &len, cipher_buffer, current_size)) {
            printf("error decrypt\n");
            return 0;
        }        
        size -= current_size;
        buffer += len;
        readed_size += len;
    }
    if (1 == end) {
        if (1 != EVP_DecryptFinal_ex(file->cipher_ctx, buffer, &len)) {
            printf("error decrypt\n");
            return 0;
        }
        readed_size += len;
    }

    return readed_size;
}

int cipher_close(CIPHER_FILE* file) {
    char cipher_buffer[4096];
    int len;
    int success = 1;
    if (ENCRYPT == file->type) {
        if (1 != EVP_CipherFinal_ex(file->cipher_ctx, cipher_buffer, &len)) {
            printf("error finish encrypt\n");
            success = 0;
            goto cleanup;
        }
        if ( len != fwrite(cipher_buffer, 1, len, file->file)) {
            printf("error write last cipher data\n");
            success = 0;
            goto cleanup;
        }
    }

    cleanup:
        fclose(file->file);
        EVP_CIPHER_CTX_free(file->cipher_ctx);
        free(file);
    return success;
}

int main() {
    CIPHER_FILE* file;
    char* key = "123456789123456789123456789123456789123456789123";
    char* text = "hello this this ";
    char plain_text[4096];
    int len;
    file = cipher_open("encrypt_test.txt", "wb", key);
    
    cipher_write(text, strlen(text), file);
    cipher_close(file);

    file = cipher_open("encrypt_test.txt", "rb", key);
    len = cipher_read(plain_text, 4096, file);
    plain_text[len] = '\0';
    printf("len %d, content %s\n", len, plain_text);
    return 0;
}